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

def start_in_progress_game():
    """Move upcoming game to in-progress status when time arrives"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT game_code, timestamp FROM results WHERE status = 'upcoming' LIMIT 1")
        next_game = cursor.fetchone()

        if next_game:
            game_code, game_time = next_game
            if datetime.now() >= game_time:
                cursor.execute("UPDATE results SET status = 'in progress' WHERE game_code = %s", (game_code,))
                conn.commit()
                notify_clients("game_started", {"game_code": game_code})

def process_in_progress_game():
    """Process the current in-progress game"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT game_code FROM results WHERE status = 'in progress' LIMIT 1")
        game = cursor.fetchone()

        if not game:
            return

        game_code = game[0]
        
        # Get distinct players with sufficient balance
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
                # If game processing failed, mark as canceled
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
            
            # Get current wallet balances for verification
            user_ids = [player[0] for player in players]
            placeholders = ','.join(['%s'] * len(user_ids))
            
            cursor.execute(f"SELECT id, wallet FROM users WHERE id IN ({placeholders})", user_ids)
            current_balances = {row[0]: float(row[1]) for row in cursor.fetchall()}
            
            # Verify all players still have sufficient balance
            valid_players = []
            for player in players:
                user_id, username, wallet = player
                if current_balances.get(user_id, 0) >= 1.0:
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
            platform_fee = round(total_pool * 0.10, 2)  # 10% platform fee
            winner_amount = round(total_pool - platform_fee, 2)  # Winner gets 90%
            
            logging.info(f"""
            Game {game_code} Economics:
            - Players: {num_players}
            - Total Pool: {total_pool}
            - Platform Fee (10%): {platform_fee}
            - Winner Amount: {winner_amount}
            """)
            
            # Select winner using cryptographically secure random
            winner = secrets.choice(valid_players)
            winner_id, winner_username = winner[0], winner[1]
            
            logging.info(f"Game {game_code}: Winner selected - {winner_username}")
            
            # Process financial transactions
            process_game_transactions(cursor, valid_players, winner_id, stake_amount, winner_amount, game_code)
            
            # Record game result
            record_game_result(cursor, game_code, valid_players, winner_username, winner_amount, total_pool, platform_fee)
            
            # Clear game queue for processed players
            clear_game_queue(cursor, valid_players)
            
            # Commit transaction
            conn.commit()
            
            # Verify final balances
            verify_final_balances(cursor, valid_players, winner_id, game_code)
            
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
        if 'conn' in locals():
            conn.rollback()
        return False

def process_game_transactions(cursor, players, winner_id, stake_amount, winner_amount, game_code):
    """Process all financial transactions for the game"""
    
    # Deduct stake from all players
    deduction_data = []
    for player in players:
        user_id = player[0]
        cursor.execute("UPDATE users SET wallet = wallet - %s WHERE id = %s", (stake_amount, user_id))
        deduction_data.append((user_id, "game_stake", -stake_amount, get_timestamp(), game_code))
    
    # Add winnings to winner
    cursor.execute("UPDATE users SET wallet = wallet + %s WHERE id = %s", (winner_amount, winner_id))
    winning_data = (winner_id, "game_win", winner_amount, get_timestamp(), game_code)
    
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
            outcome_message = %s 
        WHERE game_code = %s
        """,
        (
            winner_username, 
            winner_amount, 
            len(players), 
            total_pool, 
            platform_fee,
            f"Game {game_code}: {len(players)} players. Winner: {winner_username} won KES {winner_amount:.2f}", 
            game_code
        )
    )

def clear_game_queue(cursor, players):
    """Remove processed players from game queue"""
    user_ids = [player[0] for player in players]
    placeholders = ','.join(['%s'] * len(user_ids))
    cursor.execute(f"DELETE FROM game_queue WHERE user_id IN ({placeholders})", user_ids)

def verify_final_balances(cursor, players, winner_id, game_code):
    """Verify final wallet balances for audit purposes"""
    user_ids = [player[0] for player in players] + [winner_id]
    placeholders = ','.join(['%s'] * len(user_ids))
    
    cursor.execute(f"SELECT id, username, wallet FROM users WHERE id IN ({placeholders})", user_ids)
    final_balances = {row[0]: {"username": row[1], "balance": float(row[2])} for row in cursor.fetchall()}
    
    logging.info(f"Game {game_code} - Final Balances:")
    for user_id, data in final_balances.items():
        logging.info(f"  - {data['username']}: KES {data['balance']:.2f}")

def run_game():
    """Main game loop"""
    while not stop_event.is_set():
        try:
            schedule_upcoming_game()
            start_in_progress_game()
            process_in_progress_game()

            # Calculate sleep time until next check
            next_game_time = None
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT MIN(timestamp) FROM results WHERE status = 'upcoming'")
                row = cursor.fetchone()
                next_game_time = row[0] if row and row[0] else None

            if next_game_time:
                time_remaining = (next_game_time - datetime.now()).total_seconds()
                sleep_time = max(1, min(time_remaining, 30))
            else:
                sleep_time = 30

            time.sleep(sleep_time)

        except psycopg2.Error as e:
            logging.error(f"Database error in game loop: {e}")
            time.sleep(10)
        except Exception as e:
            logging.error(f"Unexpected error in game loop: {e}")
            time.sleep(10)

def start_game_loop():
    """Start the game processing thread"""
    print("Starting game loop thread...")
    game_thread = threading.Thread(target=run_game, daemon=True)
    game_thread.start()

def stop_game_loop():
    """Stop the game processing thread"""
    stop_event.set()
