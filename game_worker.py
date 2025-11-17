import psycopg2
import threading
import time
import secrets
import logging
from datetime import datetime, timedelta
from threading import Event
from shared import get_db_connection, notify_clients, get_timestamp, db_pool
from contextlib import contextmanager

stop_event = Event()

def generate_game_code():
    """Generate secure random game code"""
    return ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(6))

def schedule_upcoming_game():
    """Schedule next game if none exists"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp FROM results WHERE status = 'upcoming' ORDER BY timestamp DESC LIMIT 1")
            row = cursor.fetchone()

            if not row or row[0] < datetime.now():
                game_code = generate_game_code()
                game_time = (datetime.now() + timedelta(seconds=30))
                cursor.execute("INSERT INTO results (game_code, timestamp, status) VALUES (%s, %s, 'upcoming')",
                               (game_code, game_time))
                conn.commit()
                notify_clients("game_scheduled", {
                    "game_code": game_code, 
                    "timestamp": game_time.strftime("%Y-%m-%d %H:%M:%S")
                })
    except Exception as e:
        logging.error(f"Error scheduling upcoming game: {e}")

def start_in_progress_game():
    """Move upcoming game to in-progress status when time arrives"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT game_code, timestamp FROM results WHERE status = 'upcoming' ORDER BY timestamp ASC LIMIT 1")
            next_game = cursor.fetchone()

            if next_game:
                game_code, game_time = next_game
                if datetime.now() >= game_time:
                    cursor.execute("UPDATE results SET status = 'in progress' WHERE game_code = %s", (game_code,))
                    conn.commit()
                    notify_clients("game_started", {"game_code": game_code})
    except Exception as e:
        logging.error(f"Error starting in-progress game: {e}")

def process_in_progress_game():
    """Process the current in-progress game"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT game_code FROM results WHERE status = 'in progress' ORDER BY timestamp ASC LIMIT 1")
            game = cursor.fetchone()

            if not game:
                return

            game_code = game[0]
            
            # Get players from game_queue with sufficient balance
            cursor.execute("""
                SELECT DISTINCT u.id, u.username, u.wallet 
                FROM users u
                INNER JOIN game_queue gq ON u.id = gq.user_id
                WHERE u.wallet >= 1.0
            """)
            players = cursor.fetchall()
            num_players = len(players)

            if num_players >= 2:
                success = process_game_round(players, game_code)
                if not success:
                    cursor.execute("""
                        UPDATE results 
                        SET status = 'canceled', outcome_message = 'Game processing failed'
                        WHERE game_code = %s
                    """, (game_code,))
                    conn.commit()
            else:
                cursor.execute("""
                    UPDATE results
                    SET status = 'canceled', outcome_message = 'Not enough players with sufficient balance'
                    WHERE game_code = %s
                """, (game_code,))
                conn.commit()
                notify_clients("game_canceled", {"game_code": game_code})
    except Exception as e:
        logging.error(f"Error processing in-progress game: {e}")

def process_game_round(players, game_code):
    """Process a single game round with accurate financial calculations"""
    if not players or len(players) < 2:
        logging.error(f"Game {game_code}: Insufficient players")
        return False

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Start transaction
            cursor.execute("BEGIN")
            
            # Verify all players still have sufficient balance
            valid_players = []
            for player in players:
                user_id, username, wallet = player
                cursor.execute("SELECT wallet FROM users WHERE id = %s FOR UPDATE", (user_id,))
                current_wallet = cursor.fetchone()
                
                if current_wallet and float(current_wallet[0]) >= 1.0:
                    valid_players.append(player)
                else:
                    logging.warning(f"User {username} no longer has sufficient balance")
            
            if len(valid_players) < 2:
                logging.error(f"Game {game_code}: Not enough players with sufficient balance after verification")
                cursor.execute("ROLLBACK")
                return False
            
            # Calculate game economics
            stake_amount = 1.0
            num_players = len(valid_players)
            total_pool = num_players * stake_amount
            platform_fee = round(total_pool * 0.10, 2)
            winner_amount = round(total_pool - platform_fee, 2)
            
            logging.info(f"Game {game_code} Economics: Players: {num_players}, Total: {total_pool}, Fee: {platform_fee}, Winner: {winner_amount}")
            
            # Select winner
            winner = secrets.choice(valid_players)
            winner_id, winner_username = winner[0], winner[1]
            
            logging.info(f"Game {game_code}: Winner selected - {winner_username}")
            
            # Process transactions
            process_game_transactions(cursor, valid_players, winner_id, stake_amount, winner_amount, game_code)
            
            # Record result
            record_game_result(cursor, game_code, valid_players, winner_username, winner_amount, total_pool, platform_fee)
            
            # Clear queue
            clear_game_queue(cursor, valid_players)
            
            # Commit transaction
            conn.commit()
            
            # Notify clients
            notify_clients("game_completed", {
                "game_code": game_code,
                "winner": winner_username,
                "winner_amount": winner_amount,
                "total_players": num_players,
                "total_pool": total_pool
            })
            
            logging.info(f"Game {game_code} completed successfully")
            return True
            
    except Exception as e:
        logging.error(f"Error processing game {game_code}: {str(e)}")
        try:
            if 'conn' in locals():
                conn.rollback()
        except:
            pass
        return False

def process_game_transactions(cursor, players, winner_id, stake_amount, winner_amount, game_code):
    """Process all financial transactions for the game"""
    
    # Log deductions for all players (but DON'T deduct money - already done in /play)
    deduction_data = []
    for player in players:
        user_id = player[0]
        # ❌ REMOVE THIS: cursor.execute("UPDATE users SET wallet = wallet - %s WHERE id = %s", (stake_amount, user_id))
        deduction_data.append((user_id, "game_entry", -stake_amount, get_timestamp(), game_code))
    
    # Add winnings to winner
    cursor.execute("UPDATE users SET wallet = wallet + %s WHERE id = %s", (winner_amount, winner_id))
    winning_data = (winner_id, "win", winner_amount, get_timestamp(), game_code)
    
    # Log all transactions
    all_transactions = deduction_data + [winning_data]
    cursor.executemany(
        "INSERT INTO transactions (user_id, type, amount, timestamp, game_code) VALUES (%s, %s, %s, %s, %s)",
        all_transactions
    )

def record_game_result(cursor, game_code, players, winner_username, winner_amount, total_pool, platform_fee):
    """Record the final game result"""
    cursor.execute(
        """
        UPDATE results SET 
            status = 'completed', 
            winner = %s, 
            winner_amount = %s,
            num_users = %s, 
            total_amount = %s, 
            deduction = %s,
            outcome_message = %s,
            timestamp = %s
        WHERE game_code = %s
        """,
        (
            winner_username, 
            winner_amount, 
            len(players), 
            total_pool, 
            platform_fee,
            f"Game {game_code}: {len(players)} players. Winner: {winner_username} won KES {winner_amount:.2f}",
            datetime.now(),
            game_code
        )
    )

def clear_game_queue(cursor, players):
    """Remove processed players from game queue"""
    user_ids = [player[0] for player in players]
    if user_ids:
        placeholders = ','.join(['%s'] * len(user_ids))
        cursor.execute(f"DELETE FROM game_queue WHERE user_id IN ({placeholders})", user_ids)

def run_game():
    """Main game loop"""
    while not stop_event.is_set():
        try:
            schedule_upcoming_game()
            start_in_progress_game()
            process_in_progress_game()

            # Sleep between iterations
            time.sleep(5)  # Reduced from complex calculation to simple sleep

        except psycopg2.Error as e:
            logging.error(f"Database error in game loop: {e}")
            time.sleep(10)
        except Exception as e:
            logging.error(f"Unexpected error in game loop: {e}")
            time.sleep(10)

def start_game_loop():
    """Start the game processing thread"""
    print("Starting game loop thread...")
    game_thread = threading.Thread(target=run_game, daemon=True, name="GameWorker")
    game_thread.start()
    return game_thread

def stop_game_loop():
    """Stop the game processing thread"""
    stop_event.set()
