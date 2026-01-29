// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6; // Using old version to demonstrate overflow

/**
 * @title VulnerableToken
 * @notice This contract demonstrates integer overflow/underflow vulnerabilities
 * @dev Pre-Solidity 0.8.0 contracts are vulnerable without SafeMath
 */
contract VulnerableToken {
    string public name = "VulnerableToken";
    string public symbol = "VULN";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    constructor(uint256 _initialSupply) {
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;
    }
    
    /**
     * @notice Transfer tokens
     * @dev VULNERABLE: No overflow protection in Solidity < 0.8.0
     */
    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balanceOf[msg.sender] >= _value, "Insufficient balance");
        
        // VULNERABILITY: These operations can overflow/underflow
        balanceOf[msg.sender] -= _value;  // Underflow possible if check bypassed
        balanceOf[_to] += _value;          // Overflow possible with large values
        
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    
    /**
     * @notice Transfer tokens from another address
     * @dev VULNERABLE: Underflow in allowance calculation
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(balanceOf[_from] >= _value, "Insufficient balance");
        require(allowance[_from][msg.sender] >= _value, "Insufficient allowance");
        
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        
        // VULNERABILITY: Potential underflow if allowance tracking is manipulated
        allowance[_from][msg.sender] -= _value;
        
        emit Transfer(_from, _to, _value);
        return true;
    }
    
    /**
     * @notice Approve spending allowance
     */
    function approve(address _spender, uint256 _value) public returns (bool) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    /**
     * @notice Batch transfer to multiple addresses
     * @dev VULNERABLE: Loop multiplication overflow
     */
    function batchTransfer(address[] memory _receivers, uint256 _value) public returns (bool) {
        // VULNERABILITY: This multiplication can overflow
        // If _receivers.length * _value > type(uint256).max, it wraps around
        uint256 totalAmount = _receivers.length * _value;
        
        require(balanceOf[msg.sender] >= totalAmount, "Insufficient balance");
        
        balanceOf[msg.sender] -= totalAmount;
        
        for (uint256 i = 0; i < _receivers.length; i++) {
            balanceOf[_receivers[i]] += _value;
            emit Transfer(msg.sender, _receivers[i], _value);
        }
        
        return true;
    }
    
    /**
     * @notice Mint new tokens (admin only simulation)
     * @dev VULNERABLE: Total supply overflow
     */
    function mint(address _to, uint256 _amount) public {
        // VULNERABILITY: totalSupply can overflow
        totalSupply += _amount;
        balanceOf[_to] += _amount;
        
        emit Transfer(address(0), _to, _amount);
    }
}
