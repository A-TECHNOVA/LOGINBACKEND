const express = require('express');
const { body, query } = require('express-validator');
const userController = require('../controllers/userController');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();

// Validation middleware
const updateProfileValidation = [
    body('firstName')
        .optional()
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage('First name must be between 2 and 50 characters')
        .matches(/^[a-zA-Z\s]+$/)
        .withMessage('First name must contain only letters and spaces'),
    
    body('lastName')
        .optional()
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage('Last name must be between 2 and 50 characters')
        .matches(/^[a-zA-Z\s]+$/)
        .withMessage('Last name must contain only letters and spaces'),
    
    body('email')
        .optional()
        .isEmail()
        .withMessage('Valid email is required')
        .normalizeEmail(),
    
    body('phone')
        .optional()
        .matches(/^[6-9]\d{9}$/)
        .withMessage('Valid 10-digit phone number is required'),
    
    body('hostelBlock')
        .optional()
        .isIn(['A', 'B', 'C', 'D', 'E', 'F'])
        .withMessage('Invalid hostel block'),
    
    body('roomNumber')
        .optional()
        .matches(/^[A-F]\d{3}$/)
        .withMessage('Room number must be in format like A101, B205, etc.'),
    
    body('department')
        .optional()
        .trim()
        .isLength({ min: 2, max: 100 })
        .withMessage('Department must be between 2 and 100 characters')
];

const changePasswordValidation = [
    body('currentPassword')
        .notEmpty()
        .withMessage('Current password is required'),
    
    body('newPassword')
        .isLength({ min: 8 })
        .withMessage('New password must be at least 8 characters long')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
        .withMessage('New password must contain at least one uppercase letter, one lowercase letter, and one number'),
    
    body('confirmPassword')
        .custom((value, { req }) => {
            if (value !== req.body.newPassword) {
                throw new Error('Password confirmation does not match new password');
            }
            return true;
        })
];

const createUserValidation = [
    body('studentId')
        .notEmpty()
        .withMessage('Student ID is required')
        .matches(/^[A-Z0-9]+$/)
        .withMessage('Student ID must contain only alphanumeric characters')
        .isLength({ min: 3, max: 20 })
        .withMessage('Student ID must be between 3 and 20 characters'),
    
    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
        .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
    
    body('role')
        .isIn(['student', 'warden', 'dc'])
        .withMessage('Invalid role specified'),
    
    body('profile.firstName')
        .trim()
        .notEmpty()
        .withMessage('First name is required')
        .isLength({ min: 2, max: 50 })
        .withMessage('First name must be between 2 and 50 characters'),
    
    body('profile.lastName')
        .trim()
        .notEmpty()
        .withMessage('Last name is required')
        .isLength({ min: 2, max: 50 })
        .withMessage('Last name must be between 2 and 50 characters'),
    
    body('profile.email')
        .isEmail()
        .withMessage('Valid email is required')
        .normalizeEmail(),
    
    body('profile.phone')
        .matches(/^[6-9]\d{9}$/)
        .withMessage('Valid 10-digit phone number is required'),
    
    // Conditional validation for student-specific fields
    body('profile.hostelBlock')
        .if(body('role').equals('student'))
        .notEmpty()
        .withMessage('Hostel block is required for students')
        .isIn(['A', 'B', 'C', 'D', 'E', 'F'])
        .withMessage('Invalid hostel block'),
    
    body('profile.roomNumber')
        .if(body('role').equals('student'))
        .notEmpty()
        .withMessage('Room number is required for students')
        .matches(/^[A-F]\d{3}$/)
        .withMessage('Room number must be in format like A101, B205, etc.'),
    
    body('profile.yearOfStudy')
        .if(body('role').equals('student'))
        .isInt({ min: 1, max: 4 })
        .withMessage('Year of study must be between 1 and 4'),
    
    body('profile.department')
        .if(body('role').equals('student'))
        .trim()
        .notEmpty()
        .withMessage('Department is required for students')
];

const queryValidation = [
    query('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('Page must be a positive integer'),
    
    query('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('Limit must be between 1 and 100'),
    
    query('role')
        .optional()
        .isIn(['student', 'warden', 'dc'])
        .withMessage('Invalid role filter'),
    
    query('search')
        .optional()
        .trim()
        .isLength({ min: 1, max: 100 })
        .withMessage('Search term must be between 1 and 100 characters')
];

// Routes

/**
 * @route   GET /api/user/profile
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/profile', [
    authMiddleware.verifyToken
], userController.getProfile);

/**
 * @route   PUT /api/user/profile
 * @desc    Update user profile
 * @access  Private
 */
router.put('/profile', [
    authMiddleware.verifyToken,
    ...updateProfileValidation
], userController.updateProfile);

/**
 * @route   POST /api/user/change-password
 * @desc    Change user password
 * @access  Private
 */
router.post('/change-password', [
    authMiddleware.verifyToken,
    authMiddleware.sensitiveOperationLimit,
    ...changePasswordValidation
], userController.changePassword);

/**
 * @route   GET /api/user/dashboard
 * @desc    Get user dashboard data
 * @access  Private
 */
router.get('/dashboard', [
    authMiddleware.verifyToken
], userController.getDashboard);

/**
 * @route   GET /api/user/all
 * @desc    Get all users (Admin only)
 * @access  Private - Warden/DC only
 */
router.get('/all', [
    authMiddleware.verifyToken,
    authMiddleware.authorize('warden', 'dc'),
    authMiddleware.checkPermission('canViewUsers'),
    ...queryValidation
], userController.getAllUsers);

/**
 * @route   POST /api/user/create
 * @desc    Create new user (Admin only)
 * @access  Private - Warden/DC only
 */
router.post('/create', [
    authMiddleware.verifyToken,
    authMiddleware.authorize('warden', 'dc'),
    authMiddleware.checkPermission('canCreateUsers'),
    authMiddleware.sensitiveOperationLimit,
    ...createUserValidation
], userController.createUser);

/**
 * @route   GET /api/user/:userId
 * @desc    Get specific user details (Admin or Owner only)
 * @access  Private
 */
router.get('/:userId', [
    authMiddleware.verifyToken,
    authMiddleware.ownerOrAdmin('userId')
], userController.getProfile);

/**
 * @route   PUT /api/user/:userId
 * @desc    Update specific user (Admin or Owner only)
 * @access  Private
 */
router.put('/:userId', [
    authMiddleware.verifyToken,
    authMiddleware.ownerOrAdmin('userId'),
    ...updateProfileValidation
], userController.updateProfile);

/**
 * @route   DELETE /api/user/:userId
 * @desc    Deactivate user (DC only)
 * @access  Private - DC only
 */
router.delete('/:userId', [
    authMiddleware.verifyToken,
    authMiddleware.authorize('dc'),
    authMiddleware.checkPermission('canDeleteUsers')
], async (req, res) => {
    try {
        const { userId } = req.params;
        const User = require('../models/User');
        const AccessLog = require('../models/AccessLog');
        const logger = require('../utils/logger');

        // Find user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Don't allow deactivating the last DC user
        if (user.role === 'dc') {
            const dcCount = await User.countDocuments({
                role: 'dc',
                'security.isActive': true
            });

            if (dcCount <= 1) {
                return res.status(400).json({
                    success: false,
                    message: 'Cannot deactivate the last DC user'
                });
            }
        }

        // Deactivate user instead of deleting
        user.security.isActive = false;
        await user.save();

        // Log user deactivation
        await AccessLog.logAccess({
            userId: req.user.userId,
            studentId: req.user.studentId,
            action: 'USER_DEACTIVATED',
            result: 'SUCCESS',
            details: {
                deactivatedUserId: userId,
                deactivatedStudentId: user.studentId,
                deactivatedUserRole: user.role
            },
            session: {
                ip: req.ip || 'unknown',
                userAgent: req.get('User-Agent') || 'unknown'
            }
        });

        logger.security(`User reactivated: ${user.studentId} by ${req.user.studentId}`, {
            reactivatedBy: req.user.userId,
            reactivatedUserId: userId
        });

        res.json({
            success: true,
            message: 'User reactivated successfully',
            data: {
                userId: user._id,
                studentId: user.studentId,
                isActive: user.security.isActive
            }
        });

    } catch (error) {
        const logger = require('../utils/logger');
        logger.error('User reactivation error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

/**
 * @route   POST /api/user/:userId/unlock
 * @desc    Unlock user account (Admin only)
 * @access  Private - Warden/DC only
 */
router.post('/:userId/unlock', [
    authMiddleware.verifyToken,
    authMiddleware.authorize('warden', 'dc')
], async (req, res) => {
    try {
        const { userId } = req.params;
        const User = require('../models/User');
        const AccessLog = require('../models/AccessLog');
        const logger = require('../utils/logger');

        // Find user
        const user = await User.findById(userId);
        if (!user || !user.security.isActive) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (!user.isLocked) {
            return res.status(400).json({
                success: false,
                message: 'User account is not locked'
            });
        }

        // Unlock account
        user.security.loginAttempts = 0;
        user.security.lockUntil = undefined;
        await user.save();

        // Log account unlock
        await AccessLog.logAccess({
            userId: req.user.userId,
            studentId: req.user.studentId,
            action: 'ACCOUNT_UNLOCKED',
            result: 'SUCCESS',
            details: {
                unlockedUserId: userId,
                unlockedStudentId: user.studentId
            },
            session: {
                ip: req.ip || 'unknown',
                userAgent: req.get('User-Agent') || 'unknown'
            }
        });

        logger.security(`Account unlocked: ${user.studentId} by ${req.user.studentId}`, {
            unlockedBy: req.user.userId,
            unlockedUserId: userId
        });

        res.json({
            success: true,
            message: 'User account unlocked successfully'
        });

    } catch (error) {
        const logger = require('../utils/logger');
        logger.error('Account unlock error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

/**
 * @route   GET /api/user/:userId/login-history
 * @desc    Get user login history (Admin or Owner only)
 * @access  Private
 */
router.get('/:userId/login-history', [
    authMiddleware.verifyToken,
    authMiddleware.ownerOrAdmin('userId'),
    query('limit')
        .optional()
        .isInt({ min: 1, max: 50 })
        .withMessage('Limit must be between 1 and 50')
], async (req, res) => {
    try {
        const { userId } = req.params;
        const limit = parseInt(req.query.limit) || 10;
        const AccessLog = require('../models/AccessLog');

        // Get login history
        const loginHistory = await AccessLog.getUserLoginHistory(userId, limit);

        res.json({
            success: true,
            data: {
                loginHistory,
                total: loginHistory.length
            }
        });

    } catch (error) {
        const logger = require('../utils/logger');
        logger.error('Get login history error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

/**
 * @route   GET /api/user/stats/overview
 * @desc    Get user statistics overview (Admin only)
 * @access  Private - Warden/DC only
 */
router.get('/stats/overview', [
    authMiddleware.verifyToken,
    authMiddleware.authorize('warden', 'dc'),
    authMiddleware.checkPermission('canGenerateReports')
], async (req, res) => {
    try {
        const User = require('../models/User');
        const AccessLog = require('../models/AccessLog');

        // Get user statistics
        const stats = await userController.getUserStats();
        
        // Get recent login activity
        const loginStats = await AccessLog.getLoginStats(7);
        
        // Get suspicious activity
        const suspiciousActivity = await AccessLog.getSuspiciousActivity(10);

        res.json({
            success: true,
            data: {
                userStats: stats,
                loginStats,
                suspiciousActivity,
                generatedAt: new Date()
            }
        });

    } catch (error) {
        const logger = require('../utils/logger');
        logger.error('Get user stats overview error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

//module.exports = router;

// This section seems to be from a different part of the file, but I'll fix the syntax around it.
// It looks like a try-catch block without a function wrapping it.
// I'll assume it's part of a separate route handler.
// Correcting the syntax for the catch block to be a standalone block.
// Assuming the user deactivation logic is part of a function.
// Here's what that might look like:
//
// async (req, res) => {
//     try {
//         const logger = require('../utils/logger');
//         logger.security(`User deactivated: ${user.studentId} by ${req.user.studentId}`, {
//             deactivatedBy: req.user.userId,
//             deactivatedUserId: userId
//         });

//         res.json({
//             success: true,
//             message: 'User deactivated successfully'
//         });

//     } catch (error) {
//         const logger = require('../utils/logger');
//         logger.error('User deactivation error:', error);
//         res.status(500).json({
//             success: false,
//             message: 'Internal server error'
//         });
//     }
// };

/**
 * @route  POST /api/user/:userId/reactivate
 * @desc   Reactivate deactivated user (DC only)
 * @access Private - DC only
 */
router.post('/:userId/reactivate', [
    authMiddleware.verifyToken,
    authMiddleware.authorize('dc')
], async (req, res) => {
    try {
        const { userId } = req.params;
        const User = require('../models/User');
        const AccessLog = require('../models/AccessLog');
        const logger = require('../utils/logger');
        
        // Find user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (user.security.isActive) {
            return res.status(400).json({
                success: false,
                message: 'User is already active'
            });
        }

        // Reactivate user
        user.security.isActive = true;
        user.security.loginAttempts = 0;
        user.security.lockUntil = undefined;
        await user.save();

        // Log user reactivation
        await AccessLog.logAccess({
            userId: req.user.userId,
            studentId: req.user.studentId,
            action: 'USER_REACTIVATED',
            result: 'SUCCESS',
            details: {
                reactivatedUserId: userId,
                reactivatedStudentId: user.studentId,
                reactivatedUserRole: user.role
            },
            session: {
                ip: req.ip || 'unknown',
                userAgent: req.get('User-Agent') || 'unknown'
            }
        });

        logger.security(`User reactivated: ${user.studentId} by ${req.user.studentId}`, {
            reactivatedBy: req.user.userId,
            reactivatedUserId: userId
        });

        res.json({
            success: true,
            message: 'User reactivated successfully',
            data: {
                userId: user._id,
                studentId: user.studentId,
                isActive: user.security.isActive
            }
        });

    } catch (error) {
        const logger = require('../utils/logger');
        logger.error('User reactivation error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});
module.exports = router;