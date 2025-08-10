const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Ethers Test", () => {
  it("Should parse ether correctly", async () => {
    const amount = ethers.utils.parseEther("1");
    expect(amount.toString()).to.equal("1000000000000000000");
  });
});