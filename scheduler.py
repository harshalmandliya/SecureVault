"""
APScheduler - automatic key rotation based on interval from database.
Runs as background job when Flask app starts.
"""

from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from db import get_key_metadata, get_rotation_logs


def run_rotation_job():
    """
    Job executed by scheduler every hour.
    Checks if rotation interval has elapsed since last rotation.
    If so, performs rotation.
    """
    try:
        meta = get_key_metadata()
        if not meta:
            return
        interval_hours = meta['rotation_interval_hours']
        # Get last rotation time - skip if interval not elapsed
        logs = get_rotation_logs(limit=1)
        if logs and logs[0].get('rotated_at'):
            last_rotation = logs[0]['rotated_at']
            now = datetime.utcnow()
            elapsed = (now - last_rotation).total_seconds() / 3600
            if elapsed < interval_hours:
                return  # Not yet time
        # No previous rotation or interval elapsed - run rotation
        from rotate_keys import perform_rotation
        perform_rotation()
        print("[Scheduler] Key rotation completed successfully.")
    except Exception as e:
        print(f"[Scheduler] Key rotation failed: {e}")


def start_scheduler(app):
    """
    Start APScheduler.
    Job runs every hour and checks if rotation is due based on DB interval.
    """
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        run_rotation_job,
        trigger=IntervalTrigger(hours=1),
        id='rotation_job',
        replace_existing=True,
    )
    scheduler.start()
    print("[Scheduler] Automatic key rotation scheduler started (checks every hour).")
