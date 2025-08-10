const { expect } = require("chai");
const hre = require("hardhat");
const { ethers } = hre;

describe("Ethers Test", () => {
  it("Should parse ether correctly", async () => {
    console.log("Ethers version:", ethers.version);
    const amount = ethers.utils.parseEther("1");
    expect(amount.toString()).to.equal("1000000000000000000");
  });
});