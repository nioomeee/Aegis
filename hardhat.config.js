require("@nomicfoundation/hardhat-toolbox");

/**
 * @notice This is the configuration file for Hardhat.
 * @dev The most important line is `require("@nomicfoundation/hardhat-toolbox");`
 * This line imports all the necessary tools for testing, including the `ethers`
 * object that was causing the error.
 */

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.19",
};

