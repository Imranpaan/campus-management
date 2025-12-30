CREATE TABLE spaces (
    space_id INTEGER PRIMARY KEY AUTOINCREMENT,
    space_name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL,
    capacity INTEGER NOT NULL,
    availability_status VARCHAR(20) DEFAULT 'Available',
    location VARCHAR(100),
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
