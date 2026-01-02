-- Full Database Schema for Lost and Found System
-- Run this script in MySQL Workbench to create all tables

-- Users table
CREATE TABLE users (
    id int NOT NULL AUTO_INCREMENT,
    name varchar(255) NOT NULL,
    email varchar(255) NOT NULL,
    password varchar(255) NOT NULL,
    created_at timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    is_blocked tinyint DEFAULT '0',
    karma int DEFAULT '0',
    reward_points int DEFAULT '0',
    PRIMARY KEY (id),
    UNIQUE KEY email (email)
);

-- Lost items table
CREATE TABLE lost_items (
    id int NOT NULL AUTO_INCREMENT,
    item_name varchar(255) NOT NULL,
    category enum('Electronics','Bag','ID/Wallet','Personal Items','Other') NOT NULL,
    location_lost varchar(255) NOT NULL,
    date_lost date NOT NULL,
    description text,
    user_email varchar(255),
    status varchar(50),
    created_at timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    user_id int,
    image_path varchar(255),
    rejection_reason text,
    location_coords varchar(100),
    PRIMARY KEY (id)
);

-- Found items table
CREATE TABLE found_items (
    id int NOT NULL AUTO_INCREMENT,
    item_name varchar(255) NOT NULL,
    category varchar(255),
    location varchar(255),
    date_found date NOT NULL,
    image_path varchar(255) NOT NULL,
    finder_name varchar(255),
    status varchar(50),
    created_at timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    finder_email varchar(100),
    location_coords varchar(100),
    description text,
    PRIMARY KEY (id)
);

-- Claims table
CREATE TABLE claims (
    id int NOT NULL AUTO_INCREMENT,
    lost_item_id int NOT NULL,
    found_item_id int NOT NULL,
    proof_description text NOT NULL,
    proof_image_path varchar(255),
    admin_status varchar(50),
    admin_remarks text,
    claim_date timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    user_email varchar(255),
    created_at datetime NULL DEFAULT CURRENT_TIMESTAMP,
    status varchar(50),
    solved_at datetime,
    updated_at datetime NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    rejection_reason text,
    PRIMARY KEY (id),
    KEY lost_item_id (lost_item_id),
    KEY found_item_id (found_item_id),
    FOREIGN KEY (lost_item_id) REFERENCES lost_items(id),
    FOREIGN KEY (found_item_id) REFERENCES found_items(id)
);

-- Messages table
CREATE TABLE messages (
    id int NOT NULL AUTO_INCREMENT,
    claim_id int,
    sender_email varchar(255),
    message_text text,
    timestamp datetime NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY claim_id (claim_id),
    FOREIGN KEY (claim_id) REFERENCES claims(id)
);

-- Neural tags table
CREATE TABLE neural_tags (
    id int NOT NULL AUTO_INCREMENT,
    user_id int NOT NULL,
    item_name varchar(100) NOT NULL,
    item_desc text,
    unique_code varchar(100) NOT NULL,
    qr_image_path varchar(255),
    created_at timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY unique_code (unique_code),
    KEY user_id (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Tag messages table
CREATE TABLE tag_messages (
    id int NOT NULL AUTO_INCREMENT,
    tag_id int NOT NULL,
    owner_id int NOT NULL,
    finder_contact varchar(255),
    message text,
    is_read tinyint DEFAULT '0',
    created_at timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY tag_id (tag_id),
    KEY owner_id (owner_id),
    FOREIGN KEY (tag_id) REFERENCES neural_tags(id),
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

-- Audit logs table
CREATE TABLE audit_logs (
    id int NOT NULL AUTO_INCREMENT,
    item_type enum('lost','found'),
    item_id int,
    action_taken varchar(255),
    log_time timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);

-- AI matches table (for automatic matching)
CREATE TABLE ai_matches (
    id int NOT NULL AUTO_INCREMENT,
    lost_item_id int NOT NULL,
    found_item_id int NOT NULL,
    similarity_score float NOT NULL,
    created_at timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (lost_item_id) REFERENCES lost_items(id),
    FOREIGN KEY (found_item_id) REFERENCES found_items(id)
);