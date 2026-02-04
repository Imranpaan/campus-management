CREATE TABLE IF NOT EXISTS venue_bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    location TEXT NOT NULL,
    booked_by TEXT NOT NULL,
    user_role TEXT NOT NULL,
    status TEXT DEFAULT 'pending'
)
