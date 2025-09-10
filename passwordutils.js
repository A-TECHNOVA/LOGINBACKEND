const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { BCRYPT_ROUNDS } = require('../config/keys');

class PasswordUtils {
    // Hash password
    async hashPassword(password) {
        try {
            const salt = await bcrypt.genSalt(BCRYPT_ROUNDS);
            return await bcrypt.hash(password, salt);
        } catch (error) {
            throw new Error('Password hashing failed');
        }
    }

    // Compare password with hash
    async comparePassword(password, hash) {
        try {
            return await bcrypt.compare(password, hash);
        } catch (error) {
            throw new Error('Password comparison failed');
        }
    }

    // Generate random password
    generateRandomPassword(length = 12) {
        const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        let password = '';
        
        for (let i = 0; i < length; i++) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        
        return password;
    }

    // Validate password strength
    validatePasswordStrength(password) {
        const errors = [];
        
        if (password.length < 8) {
            errors.push('Password must be at least 8 characters long');
        }
        
        if (password.length > 128) {
            errors.push('Password must not exceed 128 characters');
        }
        
        if (!/[a-z]/.test(password)) {
            errors.push('Password must contain at least one lowercase letter');
        }
        
        if (!/[A-Z]/.test(password)) {
            errors.push('Password must contain at least one uppercase letter');
        }
        
        if (!/\d/.test(password)) {
            errors.push('Password must contain at least one number');
        }
        
        if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
            errors.push('Password must contain at least one special character');
        }

        // Check for common patterns
        const commonPatterns = [
            /123456/,
            /password/i,
            /qwerty/i,
            /admin/i,
            /letmein/i
        ];
        
        for (const pattern of commonPatterns) {
            if (pattern.test(password)) {
                errors.push('Password contains common patterns and is not secure');
                break;
            }
        }
        
        return {
            isValid: errors.length === 0,
            errors,
            strength: this.calculatePasswordStrength(password)
        };
    }

    // Calculate password strength score
    calculatePasswordStrength(password) {
        let score = 0;
        
        // Length bonus
        if (password.length >= 8) score += 1;
        if (password.length >= 12) score += 1;
        if (password.length >= 16) score += 1;
        
        // Character variety bonus
        if (/[a-z]/.test(password)) score += 1;
        if (/[A-Z]/.test(password)) score += 1;
        if (/\d/.test(password)) score += 1;
        if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score += 1;
        
        // Penalty for common patterns
        const commonPatterns = [/123456/, /password/i, /qwerty/i];
        for (const pattern of commonPatterns) {
            if (pattern.test(password)) {
                score -= 2;
                break;
            }
        }
        
        // Ensure score is not negative
        score = Math.max(0, score);
        
        // Convert to strength level
        if (score <= 2) return 'weak';
        if (score <= 4) return 'medium';
        if (score <= 6) return 'strong';
        return 'very-strong';
    }

    // Generate secure random token
    generateSecureToken(length = 32) {
        return crypto.randomBytes(length).toString('hex');
    }

    // Generate password reset token
    generatePasswordResetToken() {
        const token = crypto.randomBytes(20).toString('hex');
        const hashedToken = crypto
            .createHash('sha256')
            .update(token)
            .digest('hex');
            
        return {
            token,
            hashedToken,
            expires: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
        };
    }

    // Hash token for storage
    hashToken(token) {
        return crypto
            .createHash('sha256')
            .update(token)
            .digest('hex');
    }

    // Check if password has been compromised (basic check)
    async checkCompromisedPassword(password) {
        // This is a simplified version. In production, you might want to use
        // services like HaveIBeenPwned API to check against known breaches
        const commonPasswords = [
            '123456',
            'password',
            '123456789',
            '12345678',
            '12345',
            '111111',
            '1234567',
            'sunshine',
            'qwerty',
            'iloveyou',
            'princess',
            'admin',
            'welcome',
            '666666',
            'abc123',
            'football',
            '123123',
            'monkey',
            '654321',
            '!@#$%^&*'
        ];
        
        const isCompromised = commonPasswords.includes(password.toLowerCase());
        
        return {
            isCompromised,
            message: isCompromised ? 'This password appears in commonly used password lists and may be compromised' : null
        };
    }

    // Generate password based on user criteria
    generateCustomPassword(options = {}) {
        const {
            length = 12,
            includeUppercase = true,
            includeLowercase = true,
            includeNumbers = true,
            includeSpecialChars = true,
            excludeSimilar = true, // Exclude similar looking characters like 0, O, l, 1
            excludeAmbiguous = true // Exclude ambiguous characters like {, }, [, ], (, ), /, \, ', ", `, ~, ,, ;, ., <, >
        } = options;

        let charset = '';
        
        if (includeLowercase) {
            charset += excludeSimilar ? 'abcdefghijkmnopqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
        }
        
        if (includeUppercase) {
            charset += excludeSimilar ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        }
        
        if (includeNumbers) {
            charset += excludeSimilar ? '23456789' : '0123456789';
        }
        
        if (includeSpecialChars) {
            if (excludeAmbiguous) {
                charset += '!@#$%^&*-_+=?';
            } else {
                charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
            }
        }

        if (charset.length === 0) {
            throw new Error('No character sets selected for password generation');
        }

        let password = '';
        for (let i = 0; i < length; i++) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }

        return password;
    }

    // Create password policy validator
    createPasswordPolicy(policy = {}) {
        const defaultPolicy = {
            minLength: 8,
            maxLength: 128,
            requireUppercase: true,
            requireLowercase: true,
            requireNumbers: true,
            requireSpecialChars: true,
            maxRepeatingChars: 3,
            preventCommonPasswords: true,
            preventUserInfoInPassword: true
        };

        const finalPolicy = { ...defaultPolicy, ...policy };

        return (password, userInfo = {}) => {
            const errors = [];

            // Length checks
            if (password.length < finalPolicy.minLength) {
                errors.push(`Password must be at least ${finalPolicy.minLength} characters long`);
            }

            if (password.length > finalPolicy.maxLength) {
                errors.push(`Password must not exceed ${finalPolicy.maxLength} characters`);
            }

            // Character requirements
            if (finalPolicy.requireLowercase && !/[a-z]/.test(password)) {
                errors.push('Password must contain at least one lowercase letter');
            }

            if (finalPolicy.requireUppercase && !/[A-Z]/.test(password)) {
                errors.push('Password must contain at least one uppercase letter');
            }

            if (finalPolicy.requireNumbers && !/\d/.test(password)) {
                errors.push('Password must contain at least one number');
            }

            if (finalPolicy.requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
                errors.push('Password must contain at least one special character');
            }

            // Repeating characters check
            if (finalPolicy.maxRepeatingChars) {
                const regex = new RegExp(`(.)\\1{${finalPolicy.maxRepeatingChars},}`, 'i');
                if (regex.test(password)) {
                    errors.push(`Password must not contain more than ${finalPolicy.maxRepeatingChars} repeating characters`);
                }
            }

            // Common passwords check
            if (finalPolicy.preventCommonPasswords) {
                const commonCheck = this.checkCommonPassword(password);
                if (!commonCheck.isValid) {
                    errors.push(commonCheck.message);
                }
            }

            // User info in password check
            if (finalPolicy.preventUserInfoInPassword && userInfo) {
                const userInfoCheck = this.checkUserInfoInPassword(password, userInfo);
                if (!userInfoCheck.isValid) {
                    errors.push(userInfoCheck.message);
                }
            }

            return {
                isValid: errors.length === 0,
                errors,
                strength: this.calculatePasswordStrength(password),
                policy: finalPolicy
            };
        };
    }

    // Check if password contains common patterns
    checkCommonPassword(password) {
        const commonPasswords = [
            'password', '123456', 'password123', 'admin', 'qwerty',
            'letmein', 'welcome', 'monkey', 'dragon', 'master'
        ];

        const commonPatterns = [
            /^123+$/,        // Sequential numbers
            /^abc+$/i,       // Sequential letters
            /^(.)\1+$/,      // Same character repeated
            /keyboard/i,     // Keyboard patterns
            /qwerty/i,
            /asdf/i
        ];

        const lowerPassword = password.toLowerCase();

        // Check against common passwords
        if (commonPasswords.includes(lowerPassword)) {
            return {
                isValid: false,
                message: 'Password is too common and easily guessable'
            };
        }

        // Check against common patterns
        for (const pattern of commonPatterns) {
            if (pattern.test(password)) {
                return {
                    isValid: false,
                    message: 'Password contains common patterns and is easily guessable'
                };
            }
        }

        return { isValid: true };
    }

    // Check if password contains user information
    checkUserInfoInPassword(password, userInfo) {
        const lowerPassword = password.toLowerCase();
        const sensitiveFields = ['firstName', 'lastName', 'email', 'studentId'];

        for (const field of sensitiveFields) {
            if (userInfo[field]) {
                const value = userInfo[field].toString().toLowerCase();
                if (value.length >= 3 && lowerPassword.includes(value)) {
                    return {
                        isValid: false,
                        message: 'Password should not contain personal information'
                    };
                }
            }
        }

        // Check email username part
        if (userInfo.email) {
            const emailUsername = userInfo.email.split('@')[0].toLowerCase();
            if (emailUsername.length >= 3 && lowerPassword.includes(emailUsername)) {
                return {
                    isValid: false,
                    message: 'Password should not contain parts of your email address'
                };
            }
        }

        return { isValid: true };
    }

    // Password history manager
    createPasswordHistory(maxHistory = 5) {
        return {
            async addPassword(userId, hashedPassword) {
                // In a real implementation, you would store this in the database
                // This is a simplified version
                console.log(`Adding password to history for user ${userId}`);
            },

            async checkPasswordHistory(userId, newPassword) {
                // In a real implementation, you would check against stored password hashes
                // This is a simplified version
                return {
                    isReused: false,
                    message: null
                };
            }
        };
    }

    // Password expiration checker
    checkPasswordExpiration(lastPasswordChange, expirationDays = 90) {
        const now = new Date();
        const expirationDate = new Date(lastPasswordChange.getTime() + (expirationDays * 24 * 60 * 60 * 1000));
        const daysUntilExpiration = Math.ceil((expirationDate - now) / (24 * 60 * 60 * 1000));

        return {
            isExpired: now > expirationDate,
            isExpiringSoon: daysUntilExpiration <= 7 && daysUntilExpiration > 0,
            daysUntilExpiration,
            expirationDate
        };
    }
}

module.exports = new PasswordUtils();