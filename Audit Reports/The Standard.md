# The Standard - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## Medium Risk Findings
    - ### [M-01. Users can not remove some amount of collateral from contract because of wrong implementation of "canRemoveCollateral()"](#M-01)
    - ### [M-02. The hardcoded UNISWAP_FEE will result in substantial losses ](#M-02)




# <a id='contest-summary'></a>Contest Summary

### Sponsor: The Standard

### Dates: Dec 27th, 2023 - Jan 10th, 2024

[See more contest details here](https://www.codehawks.com/contests/clql6lvyu0001mnje1xpqcuvl)

# <a id='results-summary'></a>Results Summary

### Number of findings:
   - Medium: 2


## <a id='M-01'></a>M-01. Users can not remove some amount of collateral from contract because of wrong implementation of "canRemoveCollateral()"            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-12-the-standard/blob/main/contracts/SmartVaultV3.sol/#L127-L133

## Summary
When users want to remove significant amount of collateral (not all) from protocol, they fail to do so because of wrong check in canRemoveCollateral() function.
## Vulnerability Details
canRemoveCollateral() function returns boolean that indicate if user can remove some amount of collateral. This function is wrongly implemented because it checks maxMintable >= euroValueToRemove
It is a wrong implementation because "maxMintable()" function returns how much euros can user mint with given collateral as such:
```solidity
    function maxMintable() public view returns (uint256) {
        return euroCollateral() * ISmartVaultManagerV3(manager).HUNDRED_PC() / ISmartVaultManagerV3(manager).collateralRate();
    }
```
But in an edge case if user wants to remove most of their collateral without going into the liquidation area, they will encounter an "undercollateralized" even when they are not because the following check in canRemoveCollateral() will fail:
```solidity
    function canRemoveCollateral(ITokenManager.Token memory _token, uint256 _amount) private view returns (bool) {
        if (minted == 0) return true;
        uint256 currentMintable = maxMintable();
        uint256 eurValueToRemove = calculator.tokenToEurAvg(_token, _amount);
        return currentMintable >= eurValueToRemove &&
            minted <= currentMintable - eurValueToRemove;
    }
```
This can be best explained with a test. Lets dive into it:
Test Setup:

After npm installation,

1 - run "forge init --force" in the "2023-12-the-standard" folder. (Assuming you have git cloned the repo)

2 - Create remappings.txt in the root folder with following content:
```
@forge-std/=lib/forge-std/
@openzeppelin/=node_modules/@openzeppelin/
@chainlink/=node_modules/@chainlink/
```
3 - foundry.toml should look like this:
```
[profile.default]
src = 'contracts'
out = 'out'
libs = ['node_modules', 'lib']
test = 'test/foundry/'
cache_path  = 'cache_forge'
```
4 - Inside the test folder (where hardhat tests are) create a folder "foundry" and inside that folder create a file "SmartVault.t.sol" and paste the following setup inside:
```solidity
pragma solidity 0.8.17;

import {Test, console2} from "forge-std/Test.sol";
import {ERC20Mock} from "../../contracts/utils/ERC20Mock.sol";
import {EUROsMock} from "../../contracts/utils/EUROsMock.sol";
import {ChainlinkMock} from "../../contracts/utils/ChainlinkMock.sol";
import {SmartVaultManagerV5} from "../../contracts/SmartVaultManagerV5.sol";
import {SmartVaultV3} from "../../contracts/SmartVaultV3.sol";
import {PriceCalculator} from "../../contracts/utils/PriceCalculator.sol";
import {SmartVaultDeployerV3} from "../../contracts/utils/SmartVaultDeployerV3.sol";
import {TokenManagerMock} from "../../contracts/utils/TokenManagerMock.sol";
import {SmartVaultManager} from "../../contracts/utils/SmartVaultManager.sol";
import {TransparentUpgradeableProxy, ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {NFTMetadataGenerator} from "../../contracts/utils/nfts/NFTMetadataGenerator.sol";
import {SmartVaultIndex} from "../../contracts/utils/SmartVaultIndex.sol";
import {LiquidationPoolManager} from "../../contracts/LiquidationPoolManager.sol";
import {LiquidationPool} from "../../contracts/LiquidationPool.sol";
import {SwapRouterMock} from "../../contracts/utils/SwapRouterMock.sol";
import {ILiquidationPoolManager} from "../../contracts/interfaces/ILiquidationPoolManager.sol";
import {ITokenManager} from "../../contracts/interfaces/ITokenManager.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract SmartVaultV3Test is Test{
    address public deployer = vm.addr(1);
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");
    address public john = makeAddr("john");
    address public attacker = makeAddr("attacker");
    address public treasury = vm.addr(4);
    ERC20Mock public TST;
    ERC20Mock public WBTC;
    EUROsMock public EURO;
    ChainlinkMock public ClEthUsd;
    ChainlinkMock public ClEurUsd;
    ChainlinkMock public ClWbtcUsd;
    SmartVaultManagerV5 public vaultManagerV5;
    SmartVaultManagerV5 public vaultManagerV5Instance;
    address public vaultAddress;
    SmartVaultV3 public vault;
    SmartVaultDeployerV3 public vaultDeployer;
    string public ETH = "ETH";
    bytes32 public ethBytes32;
    TokenManagerMock public tokenManager;
    SmartVaultManager public vaultManagerFirstImplementation;
    TransparentUpgradeableProxy public proxy;
    ProxyAdmin public proxyAdmin;
    SmartVaultManager public vaultManagerFirstImplementationProxiedInstance;
    NFTMetadataGenerator public nftMetadataGenerator;
    SmartVaultIndex public smartVaultIndex;
    LiquidationPoolManager public liquidationPoolManager;
    LiquidationPool public liquidationPool;
    SwapRouterMock public swapRouterMock;

    function stringToBytes32(string memory source) public pure returns (bytes32 result) {
        bytes memory tempEmptyStringTest = bytes(source);
        if (tempEmptyStringTest.length == 0) {
            return 0x0;
        }

        assembly {
            result := mload(add(source, 32))
        }
    }

    function setUp() public {
        vm.startPrank(deployer);
        TST = new ERC20Mock("The Standard Token", "TST", 18);
        WBTC = new ERC20Mock("Wrapped BTC", "WBTC", 8);
        EURO = new EUROsMock();
        skip(5 hours);

        /// @notice set up chainlink mock price feeds
        ClEthUsd = new ChainlinkMock("ETH / USD");
        ClEthUsd.setPrice(237538000000);
        ClEurUsd = new ChainlinkMock("EUR / USD");
        ClEurUsd.setPrice(109586000);
        ClWbtcUsd = new ChainlinkMock("WBTC / USD");
        ClWbtcUsd.setPrice(4411586000000);

        /// @notice deploy vaultManagerV5 proxy contract
        vaultManagerFirstImplementation = new SmartVaultManager();
        nftMetadataGenerator = new NFTMetadataGenerator();
        smartVaultIndex = new SmartVaultIndex();
        ethBytes32 = stringToBytes32(ETH);
        vaultDeployer = new SmartVaultDeployerV3(ethBytes32, address(ClEurUsd));
        tokenManager = new TokenManagerMock(ethBytes32, address(ClEthUsd));
        tokenManager.addAcceptedToken(address(WBTC), address(ClWbtcUsd));
        bytes memory setUpData = abi.encodeWithSignature(
            "initialize(uint256,uint256,address,address,address,address,address,address,address)", 
            110000, 
            500, // mintFeeRate and burnFeeRate
            address(EURO), 
            address(0), // protocol
            address(0), // liquidator
            address(tokenManager), 
            address(vaultDeployer), 
            address(smartVaultIndex), 
            address(nftMetadataGenerator)
        );

        proxyAdmin = new ProxyAdmin();
        proxy = new TransparentUpgradeableProxy(address(vaultManagerFirstImplementation), address(proxyAdmin), setUpData);
        vaultManagerFirstImplementationProxiedInstance = SmartVaultManager(address(proxy));
        vaultManagerV5 = new SmartVaultManagerV5();
        proxyAdmin.upgrade(ITransparentUpgradeableProxy(address(proxy)), address(vaultManagerV5));
        vaultManagerV5Instance = SmartVaultManagerV5(address(proxy));

        /// @notice deploy liquidationPoolManager and liquidationPool (it is deployed inside liquidationPoolManager)
        liquidationPoolManager = new LiquidationPoolManager(address(TST), address(EURO), address(vaultManagerV5Instance), address(ClEurUsd), payable(treasury), 30000 );
        liquidationPool = LiquidationPool(liquidationPoolManager.pool());
        vaultManagerV5Instance.setProtocolAddress(address(liquidationPoolManager));
        vaultManagerV5Instance.setLiquidatorAddress(address(liquidationPoolManager));
        vaultManagerV5Instance = SmartVaultManagerV5(address(proxy));

        smartVaultIndex.setVaultManager(address(vaultManagerV5Instance));
        EURO.grantRole(EURO.DEFAULT_ADMIN_ROLE(), address(vaultManagerV5Instance));
        vm.stopPrank();
    }
```
After that for making testing easier do following change in SmartVaultV3.sol:
- Change "maxMintable()"s visibility to public, so that we can call this function within our tests

Now here comes our test functions. After that I will explain the tests and outputs clearly. 
```solidity
    function testCantRemoveCollateral() public {
        // deposits
        vm.deal(alice , 100e18);
        deal(address(WBTC), alice, 10e8);
        deal(address(EURO), alice, 10e18);
        vm.startPrank(alice);
        (address vaultTemp, ) = vaultManagerV5Instance.mint();
        SmartVaultV3 vault0 = SmartVaultV3(payable(vaultTemp));
        IERC20(address(WBTC)).transfer(address(vault0), 10e8);
        EURO.approve(address(vault0), 100_000e18);

        // mint
        vault0.mint(alice, 1000e18);

        // custom calculation to make test easier
        uint256 amountToRemove = 95e7;
        (, int256 price,,,) = ClWbtcUsd.latestRoundData();
        int256 euroValueOfCollat = 10e8 * price / 1e8;
        uint256 euroValueToRemove = amountToRemove * uint256(price) / 1e8;
        console2.log("Euro value of the collateral(without decimals to make it clear)", euroValueOfCollat/1e8);
        console2.log("Max Mintable Euro amount(without decimals to make it clear):",vault0.maxMintable()/1e18);
        console2.log("Euro value to remove(without decimals to make it clear):",euroValueToRemove/1e8);

        uint256 amountLeft = 10e8 - 95e7;
        uint256 eurValueLeft = amountLeft * uint256(price) / 1e8;
        console2.log("Amount left(without decimals to make it clear):",eurValueLeft/1e8);

        // withdraws
        vault0.removeCollateral(bytes32(bytes(WBTC.symbol())), amountToRemove, msg.sender);
    }

    function testMaxMintableAfterRemoval() public {
        // deposits
        vm.deal(alice , 100e18);
        deal(address(WBTC), alice, 10e8);
        deal(address(EURO), alice, 10e18);
        vm.startPrank(alice);
        (address vaultTemp, ) = vaultManagerV5Instance.mint();
        SmartVaultV3 vault0 = SmartVaultV3(payable(vaultTemp));
        IERC20(address(WBTC)).transfer(address(vault0), 5e7);
        EURO.approve(address(vault0), 100_000e18);     

        //mint
        vault0.mint(alice, 1000e18);

        console2.log("Max Mintable Euro amount(without decimals to make it clear):",vault0.maxMintable()/1e18);
    }
```
Let me explain the scenario with values and outputs of tests. (I won't use decimals in both my explanations and also in test calculations to make it easier to see)
- Alice deposits 10 WBTC.
- Alice mint 1000 euros.
- Alice decides she don't want to mint more euros and want to remove her collateral that is free.
- Alice tries to remove 9.5 WBTC.
Run "forge test --match-test testCantRemoveCollateral", output will look like this:
```
Running 1 test for test/foundry/SmartVault.t.sol:SmartVaultV3Test
[FAIL. Reason: revert: err-under-coll] testCantRemoveCollateral() (gas: 3564386)
Logs:
  Euro value of the collateral(without decimals to make it clear) 441158
  Max Mintable Euro amount(without decimals to make it clear): 365971
  Euro value to remove(without decimals to make it clear): 419100
  Amount left(without decimals to make it clear): 22057
```
As we can see initially Alice deposits "441_158" euros worth of collateral.

With this much collateral Alice can mint "365_971" euro.

Alice only minted "1_000" euros

Alice wants to remove "419_100" euro worth of collateral.

After this removal there will be "22_057" worth of collateral will remain in the collateral.

And now let's run the second test with "forge test --match-test testMaxMintableAfterRemoval", output should look like this:
```
Running 1 test for test/foundry/SmartVault.t.sol:SmartVaultV3Test
[PASS] testMaxMintableAfterRemoval() (gas: 3355971)
Logs:
  Max Mintable Euro amount(without decimals to make it clear): 18298
```
As we can see with this "22_057" worth of collateral, it is possible to mint "18_298" EUROs. But even when Alice minted only "1_000" euros, she can't remove her collateral because of the wrong check in canRemoveCollateral():
```solidity
        return currentMintable >= eurValueToRemove &&
            minted <= currentMintable - eurValueToRemove;
```
In our scenario currentMintable = 365_971 and eurValueToRemove = 419_100. Hence first check in function will return false even when alice has enough collateral to hold her position. Also the second check will revert with underflow so the return value of this function is implemented wrong.

## Impact
Impact is medium because users that are encountered this problem need to remove the protocol in order to get their collateral back. Likelihood is also medium, not all users will encounter this but some will. Hence this is a medium severity vulnerability.

## Recommendations
Change the order of removing check, and change canRemoveCollateral() function. Instead of current implementation first remove the collateral (send it back to user), then in the same function check if user is liquid enough (health factor) check, if not, revert.
Current removing pseudocode:
- Check for is it possible to remove via canRemoveCollateral() (wrongly implemented function). If not, revert.
- Send the collateral back to user.

Suggested removing pseudocode:
- Send the collateral back to user.
- Check if user is collateralised enough. If not, revert.

Final canRemoveCollateral() function can look like this:
```solidity
function isHealthyAfterRemoval():
    if minted == 0, return true;
    else:
        uint256 currentMintable = maxMintable();
        return minted <= currentMintable;
```
		

## <a id='M-02'></a>M-02. The hardcoded UNISWAP_FEE will result in substantial losses             

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-12-the-standard/blob/main/contracts/SmartVaultV3.sol/#L214-231

## Summary
Unoptimal pools will be used in uniswap because of hardcoded fee variable which leads to loss of user funds.
## Vulnerability Details
UniswapV3 pools have different fee amounts. Same pair can have 0.05% fee pool, 0.3% fee pool and also 1% fee pool. Swap function in SmartVaultV3 hardcodes the fee parameter to 3000 which corresponds to 0.3% fee as shown below:
```solidity
    function swap(bytes32 _inToken, bytes32 _outToken, uint256 _amount) external onlyOwner {
        uint256 swapFee = _amount * ISmartVaultManagerV3(manager).swapFeeRate() / ISmartVaultManagerV3(manager).HUNDRED_PC();
        address inToken = getSwapAddressFor(_inToken);
        uint256 minimumAmountOut = calculateMinimumAmountOut(_inToken, _outToken, _amount);
        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
                tokenIn: inToken,
                tokenOut: getSwapAddressFor(_outToken),
                fee: 3000,
                recipient: address(this),
                deadline: block.timestamp,
                amountIn: _amount - swapFee,
                amountOutMinimum: minimumAmountOut,
                sqrtPriceLimitX96: 0
            });
        inToken == ISmartVaultManagerV3(manager).weth() ?
            executeNativeSwapAndFee(params, swapFee) :
            executeERC20SwapAndFee(params, swapFee);
    }
```
I will give my example from USDC-WBTC pool because other pools are not liquid enough(Submitted this as a seperate vulnerability). But it is also applies to other pools (I am using the USDC-WBTC just as an example). Also it is possible for protocol to use USDC and some other tokens as specified in contest page. 

Here is the %0.05 percent fee pool address for USDC-WBTC: 0x0E4831319A50228B9e450861297aB92dee15B44F

Here is the %0.3 percent fee pool address for USDC-WBTC: 0x6985cb98CE393FCE8d6272127F39013f61e36166

As we can see %0.05 percent fee pool have nearly thrice more liquidity hence it is the optimal pool for this pair (slippage will be less), and also fee percent is 6 time less then the other pool (which is obvious). 

But because of the hardcoded fee variable in swap, the unoptimal pool will be used in swap.
## Impact
It is high likelihood because it will happen for every swap, it's impact is medium because user's will receive less worth of collateral after swap (they will lose funds) with respect to optimal pool. Hence I consider this as a medium severity vulnerability.

## Recommendations
For every pair it is best to add a struct such that it returns the optimal fee for pairs (admin can add these fee tiers), then use that variable instead of hardcoded one.
