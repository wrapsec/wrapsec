-- WrapSec database initialisation
-- Tables are created by SQLAlchemy on startup
-- This file sets up indexes and default data

-- Ensure UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Default settings
-- Inserted after tables are created by the application