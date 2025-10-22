import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import axios from 'axios';
import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export class PasswordSecurity {
  constructor() {
    this.commonPasswords = null;
    this.breachDatabase = null;
    // Legacy hash methods for cracking existing hashes - DO NOT USE FOR NEW PASSWORDS
    this.hashMethods = {
      // DEPRECATED - Only for hash cracking
      md5: (data) => crypto.createHash('md5').update(data).digest('hex'),
      sha1: (data) => crypto.createHash('sha1').update(data).digest('hex'),
      // SECURE - Use for new password hashing
      sha256: (data) => crypto.createHash('sha256').update(data).digest('hex'),
      sha512: (data) => crypto.createHash('sha512').update(data).digest('hex')
    };
    
    // Secure password hashing with bcrypt-like functionality
    this.secureHashMethods = {
      sha256WithSalt: (password, salt = null) => {
        const actualSalt = salt || crypto.randomBytes(32).toString('hex');
        const hash = crypto.createHash('sha256').update(password + actualSalt).digest('hex');
        return { hash, salt: actualSalt };
      },
      sha512WithSalt: (password, salt = null) => {
        const actualSalt = salt || crypto.randomBytes(32).toString('hex');
        const hash = crypto.createHash('sha512').update(password + actualSalt).digest('hex');
        return { hash, salt: actualSalt };
      },
      pbkdf2: (password, salt = null, iterations = 100000) => {
        const actualSalt = salt || crypto.randomBytes(32);
        const hash = crypto.pbkdf2Sync(password, actualSalt, iterations, 64, 'sha512');
        return { 
          hash: hash.toString('hex'), 
          salt: actualSalt.toString('hex'),
          iterations 
        };
      }
    };
    
    this.loadCommonPasswords();
  }

  async loadCommonPasswords() {
    try {
      const commonPasswordsPath = path.join(__dirname, '..', 'data', 'common-passwords.txt');
      const data = await fs.readFile(commonPasswordsPath, 'utf8');
      this.commonPasswords = data.split('\n').map(p => p.trim()).filter(p => p.length > 0);
    } catch (error) {
      // Create default common passwords list
      this.commonPasswords = [
        'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
        'admin', 'letmein', 'welcome', 'monkey', '1234567890', 'password1',
        'qwerty123', 'dragon', 'master', 'hello', 'login', 'passw0rd',
        'administrator', 'root', 'toor', '12345', '54321', 'pass'
      ];
      await this.saveCommonPasswords();
    }
  }

  async saveCommonPasswords() {
    try {
      const dataDir = path.join(__dirname, '..', 'data');
      await fs.mkdir(dataDir, { recursive: true });
      
      const commonPasswordsPath = path.join(dataDir, 'common-passwords.txt');
      await fs.writeFile(commonPasswordsPath, this.commonPasswords.join('\n'));
    } catch (error) {
      console.error('Failed to save common passwords:', error.message);
    }
  }

  async crackHashes(hashFile, wordlistFile = null) {
    console.log(`Starting hash cracking for: ${hashFile}`);
    
    try {
      // Read hash file
      const hashData = await fs.readFile(hashFile, 'utf8');
      const hashes = this.parseHashFile(hashData);
      
      console.log(`Found ${hashes.length} hashes to crack`);
      
      // Load wordlist
      let wordlist = this.commonPasswords;
      if (wordlistFile) {
        try {
          const wordlistData = await fs.readFile(wordlistFile, 'utf8');
          wordlist = wordlistData.split('\n').map(w => w.trim()).filter(w => w.length > 0);
          console.log(`Loaded wordlist with ${wordlist.length} words`);
        } catch (error) {
          console.log('Failed to load wordlist, using common passwords');
        }
      }

      const results = {
        total: hashes.length,
        cracked: 0,
        results: [],
        time_elapsed: 0
      };

      const startTime = Date.now();

      // Process hashes in batches for better performance
      const batchSize = 100;
      for (let i = 0; i < hashes.length; i += batchSize) {
        const batch = hashes.slice(i, i + batchSize);
        const batchResults = await this.crackHashBatch(batch, wordlist);
        
        results.results.push(...batchResults);
        results.cracked += batchResults.filter(r => r.cracked).length;
        
        // Progress update
        const progress = Math.min(i + batchSize, hashes.length);
        process.stdout.write(`\rProgress: ${progress}/${hashes.length} (${results.cracked} cracked)`);
      }

      results.time_elapsed = (Date.now() - startTime) / 1000;
      
      console.log(`\n✅ Hash cracking completed in ${results.time_elapsed}s`);
      console.log(`Cracked ${results.cracked}/${results.total} hashes (${((results.cracked/results.total)*100).toFixed(1)}%)`);
      
      // Save results
      await this.saveCrackingResults(hashFile, results);
      
      return results;
    } catch (error) {
      console.error('Hash cracking failed:', error.message);
      throw error;
    }
  }

  parseHashFile(hashData) {
    const hashes = [];
    const lines = hashData.split('\n');
    
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      
      // Support different hash file formats
      let hash, username = null, salt = null;
      
      if (trimmed.includes(':')) {
        // Format: username:hash or hash:salt
        const parts = trimmed.split(':');
        if (parts.length === 2) {
          if (this.isValidHash(parts[1])) {
            username = parts[0];
            hash = parts[1];
          } else if (this.isValidHash(parts[0])) {
            hash = parts[0];
            salt = parts[1];
          }
        } else if (parts.length >= 3) {
          // Format: username:salt:hash or similar
          username = parts[0];
          salt = parts[1];
          hash = parts[2];
        }
      } else if (this.isValidHash(trimmed)) {
        // Just a hash
        hash = trimmed;
      }
      
      if (hash) {
        hashes.push({
          original_line: line,
          hash: hash.toLowerCase(),
          username,
          salt,
          hash_type: this.detectHashType(hash),
          cracked: false,
          password: null
        });
      }
    }
    
    return hashes;
  }

  isValidHash(str) {
    // Check if string looks like a hash (hex characters and valid length)
    const hexRegex = /^[a-fA-F0-9]+$/;
    const validLengths = [32, 40, 56, 64, 96, 128]; // MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    
    return hexRegex.test(str) && validLengths.includes(str.length);
  }

  detectHashType(hash) {
    switch (hash.length) {
      case 32: return 'MD5';
      case 40: return 'SHA1';
      case 56: return 'SHA224';
      case 64: return 'SHA256';
      case 96: return 'SHA384';
      case 128: return 'SHA512';
      default: return 'Unknown';
    }
  }

  async crackHashBatch(hashes, wordlist) {
    const results = [];
    
    for (const hashInfo of hashes) {
      const result = await this.crackSingleHash(hashInfo, wordlist);
      results.push(result);
    }
    
    return results;
  }

  async crackSingleHash(hashInfo, wordlist) {
    const result = {
      hash: hashInfo.hash,
      hash_type: hashInfo.hash_type,
      username: hashInfo.username,
      cracked: false,
      password: null,
      method: null
    };

    // Determine hash function
    let hashFunction;
    switch (hashInfo.hash_type) {
      case 'MD5':
        hashFunction = this.hashMethods.md5;
        break;
      case 'SHA1':
        hashFunction = this.hashMethods.sha1;
        break;
      case 'SHA256':
        hashFunction = this.hashMethods.sha256;
        break;
      case 'SHA512':
        hashFunction = this.hashMethods.sha512;
        break;
      default:
        return result; // Unsupported hash type
    }

    // Try dictionary attack
    for (const password of wordlist) {
      let testHash;
      
      if (hashInfo.salt) {
        // Try different salt positions
        testHash = hashFunction(password + hashInfo.salt); // Salt after
        if (testHash === hashInfo.hash) {
          result.cracked = true;
          result.password = password;
          result.method = 'dictionary_salted';
          return result;
        }
        
        testHash = hashFunction(hashInfo.salt + password); // Salt before
        if (testHash === hashInfo.hash) {
          result.cracked = true;
          result.password = password;
          result.method = 'dictionary_salted';
          return result;
        }
      } else {
        testHash = hashFunction(password);
        if (testHash === hashInfo.hash) {
          result.cracked = true;
          result.password = password;
          result.method = 'dictionary';
          return result;
        }
      }
    }

    // Try common transformations
    for (const password of wordlist.slice(0, 100)) { // Limit for performance
      const transformations = this.generatePasswordTransformations(password);
      
      for (const transformed of transformations) {
        let testHash;
        
        if (hashInfo.salt) {
          testHash = hashFunction(transformed + hashInfo.salt);
          if (testHash === hashInfo.hash) {
            result.cracked = true;
            result.password = transformed;
            result.method = 'dictionary_transformed_salted';
            return result;
          }
          
          testHash = hashFunction(hashInfo.salt + transformed);
          if (testHash === hashInfo.hash) {
            result.cracked = true;
            result.password = transformed;
            result.method = 'dictionary_transformed_salted';
            return result;
          }
        } else {
          testHash = hashFunction(transformed);
          if (testHash === hashInfo.hash) {
            result.cracked = true;
            result.password = transformed;
            result.method = 'dictionary_transformed';
            return result;
          }
        }
      }
    }

    return result;
  }

  generatePasswordTransformations(password) {
    const transformations = [password];
    
    // Common transformations
    transformations.push(password.toUpperCase());
    transformations.push(password.toLowerCase());
    transformations.push(password.charAt(0).toUpperCase() + password.slice(1));
    
    // Add numbers
    for (let i = 0; i <= 999; i++) {
      if (i <= 99) {
        transformations.push(password + i);
        transformations.push(i + password);
      }
      if (i <= 9) {
        transformations.push(password + '0' + i);
      }
    }
    
    // Common substitutions
    const substitutions = {
      'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'
    };
    
    let substituted = password;
    for (const [char, sub] of Object.entries(substitutions)) {
      substituted = substituted.replace(new RegExp(char, 'gi'), sub);
    }
    if (substituted !== password) {
      transformations.push(substituted);
    }
    
    // Add common suffixes
    const suffixes = ['!', '!!', '123', '1', '2023', '2024'];
    for (const suffix of suffixes) {
      transformations.push(password + suffix);
    }
    
    return [...new Set(transformations)]; // Remove duplicates
  }

  async checkBreach(email) {
    console.log(`Checking breach status for: ${email}`);
    
    try {
      // Use Have I Been Pwned API
      const response = await axios.get(`https://haveibeenpwned.com/api/v3/breachedaccount/${email}`, {
        headers: {
          'User-Agent': 'Scorpion Security Tool'
        },
        timeout: 10000
      });

      const breaches = response.data || [];
      
      return {
        email,
        breached: breaches.length > 0,
        breach_count: breaches.length,
        breaches: breaches.map(breach => ({
          name: breach.Name,
          domain: breach.Domain,
          date: breach.BreachDate,
          description: breach.Description,
          data_classes: breach.DataClasses,
          verified: breach.IsVerified,
          sensitive: breach.IsSensitive
        })),
        check_date: new Date().toISOString()
      };
    } catch (error) {
      if (error.response && error.response.status === 404) {
        // No breaches found
        return {
          email,
          breached: false,
          breach_count: 0,
          breaches: [],
          check_date: new Date().toISOString()
        };
      }
      
      console.error('Breach check failed:', error.message);
      
      // Fallback to local breach database if available
      return this.checkLocalBreachDatabase(email);
    }
  }

  async checkLocalBreachDatabase(email) {
    // This would check against a local breach database
    // For demo, return a simulated result
    const simulatedBreaches = [
      'Collection #1', 'Exploit.in', 'LinkedIn', 'Adobe', 'MySpace'
    ];
    
    // Simulate some emails being breached (using secure hash for demo)
    const emailHash = crypto.createHash('sha256').update(email.toLowerCase()).digest('hex');
    const isBreached = parseInt(emailHash.substring(0, 2), 16) % 5 === 0; // 20% chance
    
    if (isBreached) {
      const breachCount = Math.floor(Math.random() * 3) + 1;
      const selectedBreaches = simulatedBreaches.slice(0, breachCount);
      
      return {
        email,
        breached: true,
        breach_count: breachCount,
        breaches: selectedBreaches.map(name => ({
          name,
          date: '2019-01-01',
          description: 'Local breach database entry',
          source: 'local_database'
        })),
        check_date: new Date().toISOString(),
        source: 'local_simulation'
      };
    }
    
    return {
      email,
      breached: false,
      breach_count: 0,
      breaches: [],
      check_date: new Date().toISOString(),
      source: 'local_simulation'
    };
  }

  generateSecure(length = 16, options = {}) {
    const defaults = {
      includeUppercase: true,
      includeLowercase: true,
      includeNumbers: true,
      includeSymbols: true,
      excludeSimilar: true,
      excludeAmbiguous: true
    };
    
    const config = { ...defaults, ...options };
    
    let charset = '';
    
    if (config.includeLowercase) {
      charset += 'abcdefghijklmnopqrstuvwxyz';
    }
    
    if (config.includeUppercase) {
      charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    }
    
    if (config.includeNumbers) {
      charset += '0123456789';
    }
    
    if (config.includeSymbols) {
      charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    }
    
    if (config.excludeSimilar) {
      // Remove similar looking characters
      charset = charset.replace(/[il1Lo0O]/g, '');
    }
    
    if (config.excludeAmbiguous) {
      // Remove ambiguous characters
      charset = charset.replace(/[{}[\]()\/\\'"~,;.<>]/g, '');
    }
    
    if (charset.length === 0) {
      throw new Error('No characters available for password generation');
    }
    
    let password = '';
    for (let i = 0; i < length; i++) {
      const randomIndex = crypto.randomInt(0, charset.length);
      password += charset[randomIndex];
    }
    
    // Ensure password meets complexity requirements
    if (config.includeUppercase && !/[A-Z]/.test(password) ||
        config.includeLowercase && !/[a-z]/.test(password) ||
        config.includeNumbers && !/[0-9]/.test(password) ||
        config.includeSymbols && !/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)) {
      // Regenerate if requirements not met
      return this.generateSecure(length, options);
    }
    
    return password;
  }

  analyzePasswordStrength(password) {
    const analysis = {
      password_length: password.length,
      score: 0,
      strength: 'Very Weak',
      feedback: [],
      time_to_crack: '< 1 second',
      entropy: 0
    };

    // Length scoring
    if (password.length >= 12) analysis.score += 25;
    else if (password.length >= 8) analysis.score += 15;
    else if (password.length >= 6) analysis.score += 5;

    // Character variety scoring
    if (/[a-z]/.test(password)) analysis.score += 5;
    if (/[A-Z]/.test(password)) analysis.score += 5;
    if (/[0-9]/.test(password)) analysis.score += 5;
    if (/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)) analysis.score += 10;

    // Pattern penalties
    if (/(.)\1{2,}/.test(password)) {
      analysis.score -= 10;
      analysis.feedback.push('Avoid repeated characters');
    }

    if (/123|abc|qwe|password/i.test(password)) {
      analysis.score -= 15;
      analysis.feedback.push('Avoid common patterns and words');
    }

    // Check against common passwords
    if (this.commonPasswords && this.commonPasswords.includes(password.toLowerCase())) {
      analysis.score -= 25;
      analysis.feedback.push('This is a commonly used password');
    }

    // Calculate entropy
    let charset = 0;
    if (/[a-z]/.test(password)) charset += 26;
    if (/[A-Z]/.test(password)) charset += 26;
    if (/[0-9]/.test(password)) charset += 10;
    if (/[^a-zA-Z0-9]/.test(password)) charset += 32;

    analysis.entropy = password.length * Math.log2(charset);

    // Determine strength level
    if (analysis.score >= 80) analysis.strength = 'Very Strong';
    else if (analysis.score >= 60) analysis.strength = 'Strong';
    else if (analysis.score >= 40) analysis.strength = 'Medium';
    else if (analysis.score >= 20) analysis.strength = 'Weak';

    // Estimate crack time
    const combinations = Math.pow(charset, password.length);
    const seconds = combinations / (1000000000); // Assume 1B attempts per second
    
    if (seconds < 1) analysis.time_to_crack = '< 1 second';
    else if (seconds < 60) analysis.time_to_crack = `${Math.round(seconds)} seconds`;
    else if (seconds < 3600) analysis.time_to_crack = `${Math.round(seconds/60)} minutes`;
    else if (seconds < 86400) analysis.time_to_crack = `${Math.round(seconds/3600)} hours`;
    else if (seconds < 31536000) analysis.time_to_crack = `${Math.round(seconds/86400)} days`;
    else analysis.time_to_crack = `${Math.round(seconds/31536000)} years`;

    // Add feedback
    if (password.length < 8) analysis.feedback.push('Use at least 8 characters');
    if (password.length < 12) analysis.feedback.push('Consider using 12+ characters for better security');
    if (!/[A-Z]/.test(password)) analysis.feedback.push('Add uppercase letters');
    if (!/[a-z]/.test(password)) analysis.feedback.push('Add lowercase letters');
    if (!/[0-9]/.test(password)) analysis.feedback.push('Add numbers');
    if (!/[^a-zA-Z0-9]/.test(password)) analysis.feedback.push('Add special characters');

    return analysis;
  }

  // SECURE PASSWORD HASHING METHODS - Use these for new applications
  hashPasswordSecure(password, method = 'pbkdf2') {
    console.log(`🔒 Hashing password with secure method: ${method}`);
    
    switch (method) {
      case 'sha256':
        return this.secureHashMethods.sha256WithSalt(password);
      case 'sha512':
        return this.secureHashMethods.sha512WithSalt(password);
      case 'pbkdf2':
      default:
        return this.secureHashMethods.pbkdf2(password);
    }
  }

  verifyPasswordSecure(password, storedHash, salt, method = 'pbkdf2', iterations = 100000) {
    try {
      let computedHash;
      
      switch (method) {
        case 'sha256':
          computedHash = this.secureHashMethods.sha256WithSalt(password, salt).hash;
          break;
        case 'sha512':
          computedHash = this.secureHashMethods.sha512WithSalt(password, salt).hash;
          break;
        case 'pbkdf2':
        default:
          computedHash = this.secureHashMethods.pbkdf2(password, Buffer.from(salt, 'hex'), iterations).hash;
          break;
      }
      
      return computedHash === storedHash;
    } catch (error) {
      console.error('Password verification failed:', error.message);
      return false;
    }
  }

  // Generate demonstration of secure vs insecure hashing
  demonstrateHashingSecurity(password) {
    console.log('\n🔍 Password Hashing Security Demonstration');
    console.log('==========================================');
    
    // Insecure methods (for educational purposes)
    console.log('\n❌ INSECURE METHODS (DO NOT USE):');
    const md5Hash = this.hashMethods.md5(password);
    const sha1Hash = this.hashMethods.sha1(password);
    console.log(`MD5:  ${md5Hash} (Vulnerable to rainbow tables)`);
    console.log(`SHA1: ${sha1Hash} (Vulnerable to rainbow tables)`);
    
    // Secure methods
    console.log('\n✅ SECURE METHODS (RECOMMENDED):');
    const sha256Salted = this.secureHashMethods.sha256WithSalt(password);
    const sha512Salted = this.secureHashMethods.sha512WithSalt(password);
    const pbkdf2Hash = this.secureHashMethods.pbkdf2(password);
    
    console.log(`SHA256+Salt: ${sha256Salted.hash}`);
    console.log(`Salt:        ${sha256Salted.salt}`);
    console.log(`SHA512+Salt: ${sha512Salted.hash}`);
    console.log(`Salt:        ${sha512Salted.salt}`);
    console.log(`PBKDF2:      ${pbkdf2Hash.hash}`);
    console.log(`Salt:        ${pbkdf2Hash.salt}`);
    console.log(`Iterations:  ${pbkdf2Hash.iterations}`);
    
    return {
      insecure: { md5: md5Hash, sha1: sha1Hash },
      secure: { sha256Salted, sha512Salted, pbkdf2Hash }
    };
  }

  async saveCrackingResults(hashFile, results) {
    try {
      const resultsDir = path.join(process.cwd(), '.scorpion', 'password-results');
      await fs.mkdir(resultsDir, { recursive: true });
      
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const basename = path.basename(hashFile, path.extname(hashFile));
      const resultFile = path.join(resultsDir, `crack_results_${basename}_${timestamp}.json`);
      
      await fs.writeFile(resultFile, JSON.stringify(results, null, 2));
      console.log(`Results saved: ${resultFile}`);
    } catch (error) {
      console.error('Failed to save cracking results:', error.message);
    }
  }
}