// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title SafeBank
 * @notice A secure bank contract implementing best practices
 * @dev This contract demonstrates proper security patterns
 */
contract SafeBank is ReentrancyGuard, Ownable, Pausable {
    mapping(address => uint256) private balances;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    
    constructor() Ownable() {}
    
    /**
     * @notice Deposit ETH into the bank
     */
    function deposit() external payable whenNotPaused {
        require(msg.value > 0, "Must deposit something");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    /**
     * @notice Withdraw deposited ETH
     * @dev Protected against reentrancy with nonReentrant modifier
     *      Uses checks-effects-interactions pattern
     */
    function withdraw(uint256 _amount) external nonReentrant whenNotPaused {
        // Checks
        uint256 balance = balances[msg.sender];
        require(balance >= _amount, "Insufficient balance");
        require(_amount > 0, "Amount must be positive");
        
        // Effects - state update BEFORE external call
        balances[msg.sender] = balance - _amount;
        
        // Interactions - external call AFTER state update
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");
        
        emit Withdrawal(msg.sender, _amount);
    }
    
    /**
     * @notice Get user balance
     * @param _user Address to check
     * @return User's balance
     */
    function getBalance(address _user) external view returns (uint256) {
        return balances[_user];
    }
    
    /**
     * @notice Pause the contract
     * @dev Only owner can pause
     */
    function pause() external onlyOwner {
        _pause();
    }
    
    /**
     * @notice Unpause the contract
     * @dev Only owner can unpause
     */
    function unpause() external onlyOwner {
        _unpause();
    }
    
    /**
     * @notice Emergency withdraw by owner
     * @dev Uses proper access control with onlyOwner
     * @param _to Recipient address
     */
    function emergencyWithdraw(address _to) external onlyOwner nonReentrant {
        require(_to != address(0), "Invalid address");
        uint256 amount = address(this).balance;
        require(amount > 0, "No funds to withdraw");
        
        (bool success, ) = _to.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
