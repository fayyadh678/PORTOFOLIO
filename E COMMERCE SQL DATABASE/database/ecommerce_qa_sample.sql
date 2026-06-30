-- =========================================================
-- QA Database Testing Portfolio
-- Project: Mini E-Commerce Database Testing
-- Database Engine: SQLite
-- Purpose: Practice SQL validation for QA Manual / QA Automation Intern Portfolio
-- =========================================================

PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS payments;
DROP TABLE IF EXISTS order_items;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    user_id INTEGER PRIMARY KEY,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT,
    status TEXT NOT NULL CHECK (status IN ('active', 'inactive')),
    created_at TEXT NOT NULL
);

CREATE TABLE products (
    product_id INTEGER PRIMARY KEY,
    product_name TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL CHECK (price > 0),
    stock_quantity INTEGER NOT NULL CHECK (stock_quantity >= 0),
    is_active INTEGER NOT NULL CHECK (is_active IN (0, 1))
);

CREATE TABLE orders (
    order_id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    order_date TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'paid', 'shipped', 'completed', 'cancelled')),
    total_amount REAL NOT NULL CHECK (total_amount >= 0),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE order_items (
    order_item_id INTEGER PRIMARY KEY,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    unit_price REAL NOT NULL CHECK (unit_price >= 0),
    line_total REAL NOT NULL CHECK (line_total >= 0),
    FOREIGN KEY (order_id) REFERENCES orders(order_id),
    FOREIGN KEY (product_id) REFERENCES products(product_id)
);

CREATE TABLE payments (
    payment_id INTEGER PRIMARY KEY,
    order_id INTEGER NOT NULL,
    payment_method TEXT NOT NULL CHECK (payment_method IN ('bank_transfer', 'e_wallet', 'credit_card', 'cash_on_delivery')),
    payment_status TEXT NOT NULL CHECK (payment_status IN ('pending', 'paid', 'failed', 'refunded')),
    paid_amount REAL NOT NULL CHECK (paid_amount >= 0),
    paid_at TEXT,
    FOREIGN KEY (order_id) REFERENCES orders(order_id)
);

INSERT INTO users (user_id, full_name, email, phone, status, created_at) VALUES
(1, 'Fayyadh Ahmad', 'fayyadh@example.com', '085710759738', 'active', '2026-06-01'),
(2, 'Nadia Putri', 'nadia@example.com', '081234567890', 'active', '2026-06-02'),
(3, 'Raka Pratama', 'raka@example.com', '082233445566', 'active', '2026-06-03'),
(4, 'Salsa Maharani', 'salsa@example.com', '087788990011', 'inactive', '2026-06-04'),
(5, 'Dimas Saputra', 'dimas@example.com', '089911223344', 'active', '2026-06-05');

INSERT INTO products (product_id, product_name, category, price, stock_quantity, is_active) VALUES
(101, 'Sauce Labs Backpack', 'Bag', 29.99, 20, 1),
(102, 'Sauce Labs Bike Light', 'Accessory', 9.99, 35, 1),
(103, 'Sauce Labs Bolt T-Shirt', 'Clothing', 15.99, 50, 1),
(104, 'Sauce Labs Fleece Jacket', 'Clothing', 49.99, 10, 1),
(105, 'Sauce Labs Onesie', 'Clothing', 7.99, 0, 1),
(106, 'Test.allTheThings() T-Shirt', 'Clothing', 15.99, 15, 1);

-- Note: Order 1004 intentionally has incorrect total_amount for testing purpose.
INSERT INTO orders (order_id, user_id, order_date, status, total_amount) VALUES
(1001, 1, '2026-06-10', 'completed', 39.98),
(1002, 2, '2026-06-11', 'paid', 15.99),
(1003, 3, '2026-06-12', 'cancelled', 0.00),
(1004, 1, '2026-06-13', 'completed', 69.98),
(1005, 5, '2026-06-14', 'pending', 49.99);

INSERT INTO order_items (order_item_id, order_id, product_id, quantity, unit_price, line_total) VALUES
(1, 1001, 101, 1, 29.99, 29.99),
(2, 1001, 102, 1, 9.99, 9.99),
(3, 1002, 103, 1, 15.99, 15.99),
(4, 1004, 104, 1, 49.99, 49.99),
(5, 1004, 101, 1, 29.99, 29.99),
(6, 1005, 104, 1, 49.99, 49.99);

-- Note: Payment 504 intentionally has a mismatch with order 1004 total_amount for testing purpose.
INSERT INTO payments (payment_id, order_id, payment_method, payment_status, paid_amount, paid_at) VALUES
(501, 1001, 'e_wallet', 'paid', 39.98, '2026-06-10 10:15:00'),
(502, 1002, 'bank_transfer', 'paid', 15.99, '2026-06-11 13:20:00'),
(503, 1003, 'cash_on_delivery', 'failed', 0.00, NULL),
(504, 1004, 'credit_card', 'paid', 79.98, '2026-06-13 16:05:00'),
(505, 1005, 'bank_transfer', 'pending', 0.00, NULL);
