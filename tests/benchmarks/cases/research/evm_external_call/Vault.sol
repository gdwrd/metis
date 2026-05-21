contract Vault {
    function withdraw(bytes calldata payload) public payable {
        msg.sender.call(payload);
    }

    function withdrawSafe(bytes calldata payload) public nonReentrant {
        require(msg.sender != address(0));
        msg.sender.call(payload);
    }
}
