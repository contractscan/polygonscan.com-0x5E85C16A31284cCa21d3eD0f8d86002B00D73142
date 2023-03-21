//SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.17;

import "./ERC1967Proxy.sol";

/** @title Proxy contract that maintains a group of owners
    @dev Should be created by an address to be recognized as an owner
 */
contract GuardianProxy is ERC1967Proxy {
    address private immutable _trustedForwarder;

    constructor(address admin, address target, address trustedForwarder, bytes memory initializeData) ERC1967Proxy(target, initializeData) {
        _trustedForwarder = trustedForwarder;
        _changeAdmin(admin);
    }

    /** @notice Retrieves the address this contract is proxying to
        @return implementation address of the implementation contract
     */
    function getImplementationAddress() external view returns (address) {
        return _implementation();
    }

    modifier onlyAdmin {
        require(isAdmin(), "Message sender is not proxy admin");
        _;
    }

    /** @notice Changes the admin of this contract
        Message sender must be an admin
     */
    function changeAdmin(address newAdmin) external virtual onlyAdmin {
        _changeAdmin(newAdmin);
    }

    /** @notice Changes the address this contract is proxying to
        Message sender must be an admin
     */
    function upgradeTo(address newTarget) external onlyAdmin {
        _upgradeTo(newTarget);
    }

    /**
     * @notice Changes the address this contract is proxying to and calls a function from the new implementation
        Message sender must be an admin
     */
    function upgradeToAndCall(address newImplementation, bytes calldata data) external onlyAdmin {
        _upgradeToAndCall(newImplementation, data, true);
    }

    /** @notice Check is message sender is an admin
        @return isAdmin whether message sender is an admin
     */
    function isAdmin() public view returns (bool) {
        return _msgSender() == _getAdmin();
    }

    // ========= ERC2771 =========
    // We implement the functions here instead of extending ERC2771Context in order to prevent function clashing 
    // by the isTrustedForwarder function

    /** @notice Check if an address is the trusted forwarder
        @dev Equivalent to ERC2771's isTrustedForwarder
        @param forwarder address to check
        @return isTrustedForwarder whether the specified address is the trusted forwarder
     */
    function isProxyTrustedForwarder(address forwarder) external view virtual returns (bool) {
        return _isTrustedForwarder(forwarder);
    }

    function _isTrustedForwarder(address forwarder) internal view virtual returns (bool) {
        return forwarder == _trustedForwarder;
    }

    function _msgSender() internal view virtual returns (address sender) {
        if (_isTrustedForwarder(msg.sender)) {
            // The assembly code is more direct than the Solidity version using `abi.decode`.
            /// @solidity memory-safe-assembly
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            return msg.sender;
        }
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        if (_isTrustedForwarder(msg.sender)) {
            return msg.data[:msg.data.length - 20];
        } else {
            return msg.data;
        }
    }
}