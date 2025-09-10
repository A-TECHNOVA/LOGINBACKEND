const express = require('express');
const { body } = require('express-validator');
const authController = require('../controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();

// Validation middleware
const loginValidation = [
    body('studentId')
        .notEmpty()
        .withMessage('Student ID is required')
        .isLength({ min: 3, max: 20 })
        .withMessage('Student ID must be between 3 and 20 characters')
        .matches(/^[A-Z0-9]+$/)
        .withMessage('Student ID must contain only alphanumeric characters'),
    
    body('password')
        .notEmpty()
        .withMessage('Password is required')
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters long'),
    
    body('role')
        .optional()
        .isIn(['student', 'warden', 'dc'])
        .withMessage('Invalid role specified')
];

const forgotPasswordValidation = [
    body('studentId')
        .notEmpty()
        .withMessage('Student ID is required')
        .matches(/^[A-Z0-9]+$/)
        .withMessage('Invalid Student ID format'),
    
    body('email')
        .isEmail()
        .withMessage('Valid email is required')
        .normalizeEmail()
];

const resetPasswordValidation = [
    body('token')
        .notEmpty()
        .withMessage('Reset token is required')
        .isLength({ min: 40, max: 40 })
        .withMessage('Invalid token format'),
    
    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
        .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number')
];

// Routes

/**
 * @route   POST /api/auth/login
 * @desc    User login
 * @access  Public
 */
router.post('/login', [
    authMiddleware.addRequestMetadata,
    authMiddleware.validateStudentId,
    ...loginValidation
], authController.login);

/**
 * @route   POST /api/auth/logout
 * @desc    User logout
 * @access  Private
 */
router.post('/logout', [
    authMiddleware.verifyToken
], authController.logout);

/**
 * @route   POST /api/auth/forgot-password
 * @desc    Request password reset
 * @access  Public
 */
router.post('/forgot-password', [
    authMiddleware.addRequestMetadata,
    authMiddleware.sensitiveOperationLimit,
    ...forgotPasswordValidation
], authController.forgotPassword);

/**
 * @route   POST /api/auth/reset-password
 * @desc    Reset password with token
 * @access  Public
 */
router.post('/reset-password', [
    authMiddleware.addRequestMetadata,
    authMiddleware.sensitiveOperationLimit,
    ...resetPasswordValidation
], authController.resetPassword);

/**
 * @route   GET /api/auth/verify-token
 * @desc    Verify JWT token validity
 * @access  Private
 */
router.get('/verify-token', [
    authMiddleware.verifyToken
], authController.verifyToken);

/**
 * @route   GET /api/auth/me
 * @desc    Get current user info
 * @access  Private
 */
router.get('/me', [
    authMiddleware.verifyToken
], authController.verifyToken);

module.exports = router;