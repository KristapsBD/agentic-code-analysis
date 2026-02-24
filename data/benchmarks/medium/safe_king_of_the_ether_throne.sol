// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/**
 * @title KingOfEther
 * @dev A contract where users can claim the throne by sending more Ether than the current king. 
 *      The previous king is refunded the amount they sent.
 */
contract KingOfEther {
    
    // The address of the current king
    address public king;
    
    // The amount of Ether currently held by the contract, representing the last king's deposit
    uint256 public balance;

    // Mapping to store the Ether balances of users who are not the current king
    mapping(address => uint256) public balances;

    /**
     * @dev Allows users to claim the throne by sending more Ether than the current balance.
     *      The previous king is refunded the amount of Ether they sent.
     * @notice The function stores the Ether of the previous king safely before updating the state.
     * @dev The function is vulnerable to a potential Denial of Service (DoS) attack if the 
     *      previous king's refund fails (e.g., the previous king's fallback function doesn't accept Ether).
     */
    function claimThrone() external payable {
        // Ensure the sender sends more Ether than the current balance to claim the throne
        require(msg.value > balance, "Need to pay more to become the king");

        // Store the current king's balance safely for later refund
        balances[king] += balance;

        // Update the balance to the new sender's Ether deposit
        balance = msg.value;

        // Set the new king as the sender of the transaction
        king = msg.sender;
    }

    /**
     * @dev Allows users to withdraw their Ether that has been safely stored in the contract.
     *      The current king is restricted from withdrawing their funds.
     * @notice The function uses `call` to transfer Ether to users.
     * @dev This function prevents the current king from withdrawing Ether as they are in control 
     *      of the throne. The `require` check ensures this.
     */
    function withdraw() public {
        // Ensure the current king cannot withdraw their balance
        require(msg.sender != king, "Current king cannot withdraw");

        // Fetch the balance of the user requesting the withdrawal
        uint256 amount = balances[msg.sender];

        // Reset the user's balance to avoid re-entrancy issues
        balances[msg.sender] = 0;

        // Attempt to send the Ether to the user, ensuring that it was successful
        (bool sent,) = msg.sender.call{value: amount}("");
        require(sent, "Failed to send Ether");
    }
}