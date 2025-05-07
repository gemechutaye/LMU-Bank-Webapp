/**
 * Crypto Transfer Animation System
 * 
 * This file handles animations for cryptocurrency transfers.
 * It includes security measures to prevent XSS and other client-side attacks.
 */

// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    
    // Constants for animation
    const ANIMATION_DURATION = 2000; // ms
    
    /**
     * Sanitize string to prevent XSS
     * @param {string} str - String to sanitize
     * @return {string} Sanitized string
     */
    function sanitizeString(str) {
        if (!str) return '';
        
        // Create a temporary div element
        const tempDiv = document.createElement('div');
        
        // Set the div's text content to the input string (this escapes HTML)
        tempDiv.textContent = str;
        
        // Return the escaped HTML
        return tempDiv.innerHTML;
    }
    
    /**
     * Create cryptocurrency coin element for animation
     * @param {string} symbol - Cryptocurrency symbol
     * @param {string} color - Coin color
     * @return {HTMLElement} Coin element
     */
    function createCoinElement(symbol, color) {
        // Sanitize inputs
        symbol = sanitizeString(symbol);
        color = sanitizeString(color);
        
        const coin = document.createElement('div');
        coin.className = 'animated-coin';
        coin.style.backgroundColor = color || '#f7931a';
        coin.style.color = '#fff';
        coin.style.width = '50px';
        coin.style.height = '50px';
        coin.style.borderRadius = '25px';
        coin.style.display = 'flex';
        coin.style.justifyContent = 'center';
        coin.style.alignItems = 'center';
        coin.style.fontWeight = 'bold';
        coin.style.position = 'absolute';
        coin.style.left = '0';
        coin.style.top = '50%';
        coin.style.transform = 'translateY(-50%)';
        coin.style.boxShadow = '0 4px 8px rgba(0,0,0,0.2)';
        coin.style.zIndex = '1000';
        coin.textContent = symbol;
        
        return coin;
    }
    
    /**
     * Animate cryptocurrency transfer
     * @param {string} cryptoSymbol - Cryptocurrency symbol
     * @param {string} cryptoColor - Cryptocurrency color
     */
    function animateTransfer(cryptoSymbol, cryptoColor) {
        // Get animation container
        const container = document.querySelector('.transfer-animation-container');
        if (!container) return;
        
        // Create coin element
        const coin = createCoinElement(cryptoSymbol, cryptoColor);
        container.appendChild(coin);
        
        // Animate the coin from left to right
        setTimeout(() => {
            coin.style.transition = `transform ${ANIMATION_DURATION}ms cubic-bezier(0.4, 0, 0.2, 1), left ${ANIMATION_DURATION}ms linear`;
            coin.style.left = 'calc(100% - 50px)';
            
            // Add a small bounce effect
            coin.animate([
                { transform: 'translateY(-50%)' },
                { transform: 'translateY(-80%)' },
                { transform: 'translateY(-50%)' }
            ], {
                duration: ANIMATION_DURATION,
                easing: 'cubic-bezier(0.4, 0, 0.2, 1)'
            });
            
            // Remove the coin after animation completes
            setTimeout(() => {
                container.removeChild(coin);
            }, ANIMATION_DURATION + 100);
        }, 100);
    }
    
    /**
     * Initialize the transfer form animation
     */
    function initTransferFormAnimation() {
        const transferForm = document.getElementById('transfer-form');
        const cryptoSelect = document.getElementById('crypto_type');
        
        if (transferForm && cryptoSelect) {
            // Preview animation when crypto type changes
            cryptoSelect.addEventListener('change', function() {
                const selectedOption = this.options[this.selectedIndex];
                const cryptoText = selectedOption.text || '';
                
                // Extract the crypto symbol from the option text
                const matches = cryptoText.match(/^([A-Z]+)/);
                if (matches && matches[1]) {
                    const symbol = matches[1];
                    
                    // Get color based on symbol
                    let color = '#f7931a'; // Default color
                    
                    // Map of crypto symbols to their brand colors
                    const colorMap = {
                        'BTC': '#f7931a',
                        'ETH': '#627eea',
                        'XRP': '#0f0e0e',
                        'LTC': '#d3d3d3',
                        'DOGE': '#c3a634'
                    };
                    
                    if (colorMap[symbol]) {
                        color = colorMap[symbol];
                    }
                    
                    // Show preview animation
                    animateTransfer(symbol, color);
                }
            });
            
            // Submit handler with animation
            transferForm.addEventListener('submit', function(event) {
                // Don't prevent default - let the form submit normally
                
                // Get selected crypto for animation
                const selectedOption = cryptoSelect.options[cryptoSelect.selectedIndex];
                const cryptoText = selectedOption.text || '';
                
                // Extract the crypto symbol from the option text
                const matches = cryptoText.match(/^([A-Z]+)/);
                if (matches && matches[1]) {
                    const symbol = matches[1];
                    
                    // Get color based on symbol
                    let color = '#f7931a'; // Default color
                    
                    // Map of crypto symbols to their brand colors
                    const colorMap = {
                        'BTC': '#f7931a',
                        'ETH': '#627eea',
                        'XRP': '#0f0e0e',
                        'LTC': '#d3d3d3',
                        'DOGE': '#c3a634'
                    };
                    
                    if (colorMap[symbol]) {
                        color = colorMap[symbol];
                    }
                    
                    // Show animation
                    animateTransfer(symbol, color);
                }
            });
        }
    }
    
    /**
     * Add visual effects to crypto balance cards
     */
    function initCryptoCards() {
        const cryptoCards = document.querySelectorAll('.crypto-card');
        
        cryptoCards.forEach(card => {
            card.addEventListener('mouseenter', function() {
                this.style.transform = 'translateY(-10px)';
                this.style.boxShadow = '0 15px 30px rgba(0,0,0,0.2)';
            });
            
            card.addEventListener('mouseleave', function() {
                this.style.transform = 'translateY(0)';
                this.style.boxShadow = '0 5px 15px rgba(0,0,0,0.1)';
            });
        });
    }
    
    // Initialize all animations and interactions
    initTransferFormAnimation();
    initCryptoCards();
});
