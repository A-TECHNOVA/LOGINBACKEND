const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { BCRYPT_ROUNDS } = require('../config/keys');

const userSchema = new mongoose.Schema({
    studentId: {
        type: String,
        required: [true, 'Student ID is required'],
        unique: true,
        trim: true,
        uppercase: true,
        match: [/^[A-Z0-9]+$/, 'Student ID must contain only alphanumeric characters']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters long']
    },
    role: {
        type: String,
        required: true,
        enum: ['student', 'warden', 'dc'],
        default: 'student'
    },
    profile: {
        firstName: {
            type: String,
            required: [true, 'First name is required'],
            trim: true,
            maxlength: [50, 'First name cannot exceed 50 characters']
        },
        lastName: {
            type: String,
            required: [true, 'Last name is required'],
            trim: true,
            maxlength: [50, 'Last name cannot exceed 50 characters']
        },
        email: {
            type: String,
            required: [true, 'Email is required'],
            unique: true,
            lowercase: true,
            match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
        },
        phone: {
            type: String,
            required: [true, 'Phone number is required'],
            match: [/^[6-9]\d{9}$/, 'Please enter a valid phone number']
        },
        hostelBlock: {
            type: String,
            required: function() { return this.role === 'student'; },
            enum: ['A', 'B', 'C', 'D', 'E', 'F'],
            uppercase: true
        },
        roomNumber: {
            type: String,
            required: function() { return this.role === 'student'; },
            match: [/^[A-F]\d{3}$/, 'Room number must be in format like A101, B205, etc.']
        },
        yearOfStudy: {
            type: Number,
            required: function() { return this.role === 'student'; },
            min: [1, 'Year of study must be between 1 and 4'],
            max: [4, 'Year of study must be between 1 and 4']
        },
        department: {
            type: String,
            required: function() { return this.role === 'student'; },
            trim: true
        }
    },
    security: {
        isActive: {
            type: Boolean,
            default: true
        },
        lastLogin: {
            type: Date
        },
        loginAttempts: {
            type: Number,
            default: 0
        },
        lockUntil: {
            type: Date
        },
        passwordResetToken: {
            type: String
        },
        passwordResetExpires: {
            type: Date
        }
    }
}, {
    timestamps: true,
    toJSON: {
        transform: function(doc, ret) {
            delete ret.password;
            delete ret.security.passwordResetToken;
            delete ret.__v;
            return ret;
        }
    }
});

// Index for faster queries
userSchema.index({ studentId: 1 });
userSchema.index({ 'profile.email': 1 });
userSchema.index({ role: 1 });

// Virtual for checking if account is locked
userSchema.virtual('isLocked').get(function() {
    return !!(this.security.lockUntil && this.security.lockUntil > Date.now());
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(BCRYPT_ROUNDS);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
    if (this.isLocked) {
        throw new Error('Account is temporarily locked');
    }
    
    const isMatch = await bcrypt.compare(candidatePassword, this.password);
    
    if (!isMatch) {
        this.security.loginAttempts += 1;
        
        // Lock account after 5 failed attempts for 2 hours
        if (this.security.loginAttempts >= 5) {
            this.security.lockUntil = Date.now() + 2 * 60 * 60 * 1000; // 2 hours
        }
        
        await this.save();
        return false;
    } else {
        // Reset login attempts on successful login
        if (this.security.loginAttempts > 0) {
            this.security.loginAttempts = 0;
            this.security.lockUntil = undefined;
            await this.save();
        }
        return true;
    }
};

// Update last login
userSchema.methods.updateLastLogin = async function() {
    this.security.lastLogin = new Date();
    await this.save();
};

// Generate password reset token
userSchema.methods.generatePasswordResetToken = function() {
    const resetToken = require('crypto').randomBytes(20).toString('hex');
    
    this.security.passwordResetToken = require('crypto')
        .createHash('sha256')
        .update(resetToken)
        .digest('hex');
    
    this.security.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
    
    return resetToken;
};

module.exports = mongoose.model('User', userSchema);