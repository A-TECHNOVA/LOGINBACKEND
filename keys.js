module.exports = {
    // JWT Configuration
    JWT_SECRET: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production',
    JWT_EXPIRE: process.env.JWT_EXPIRE || '1d',
    JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key',
    JWT_REFRESH_EXPIRE: process.env.JWT_REFRESH_EXPIRE || '7d',

    // Database
    MONGODB_URI: process.env.MONGODB_URI || 'mongodb://localhost:27017/hostel_management',

    // Email Configuration
    EMAIL_HOST: process.env.EMAIL_HOST || 'smtp.gmail.com',
    EMAIL_PORT: process.env.EMAIL_PORT || 587,
    EMAIL_USER: process.env.EMAIL_USER,
    EMAIL_PASS: process.env.EMAIL_PASS,
    EMAIL_FROM: process.env.EMAIL_FROM || 'noreply@hostelmanagement.com',

    // Frontend URL
    FRONTEND_URL: process.env.FRONTEND_URL || 'http://localhost:3000',

    // Password Reset
    RESET_PASSWORD_EXPIRE: process.env.RESET_PASSWORD_EXPIRE || '10', // minutes

    // Bcrypt rounds
    BCRYPT_ROUNDS: parseInt(process.env.BCRYPT_ROUNDS) || 12,

    // Server Configuration
    PORT: process.env.PORT || 5000,
    NODE_ENV: process.env.NODE_ENV || 'development',

    // Rate Limiting
    RATE_LIMIT_WINDOW: process.env.RATE_LIMIT_WINDOW || 15, // minutes
    RATE_LIMIT_MAX: process.env.RATE_LIMIT_MAX || 100,
    AUTH_RATE_LIMIT_MAX: process.env.AUTH_RATE_LIMIT_MAX || 5
};