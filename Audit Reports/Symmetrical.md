# Symmetrical Finance Audit Competition

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)

- ## Medium Risk Findings
    - ### [M-01. Malicious PartyB can force their PartyA's into liquidation](#M-01)
    - ### [M-02. System can get into a state where user actions are paused while liquidations not](#M-02)
    - ### [M-03. User account and its funds got stuck in liquidation phase](#M-03)



# <a id='contest-summary'></a>Contest Summary

### Dates: Jun 15th, 2023 - July 3rd, 2023


# <a id='results-summary'></a>Results Summary

### Number of findings:
   - Medium: 3

		
# Medium Risk Findings


## <a id='M-01'></a>M-01. Malicious PartyB can force their PartyA's into liquidation            

## Summary

PartyB's have too many privileges and system is running around their actions and choices. Using these privileges, if partyB sees that their partyA is on the road to liquidation but trying to get rid of: they can block their partyA's request by simply locking new quotes and not accepting other requests.

## Vulnerability Details
In Symmetrical, the control over funds are mostly within the hands of partyB. Although this is the intented choice, it actually can create opportunities for partyB's to use them maliciously.
Let's examine one scenario:

1. PartyA's funds are losing value and hence he/she is at the risk of liquidation.
2. PartyA wants to save their funds. The ways to prevent liquidity are:
    1. Closing position (via requestToClosePosition function)
    2. Opening hedge positions (via sendQuote function)
    3. Depositing and/or allocating new funds

Assuming user can not use option 3, now I will show how partyB can maliciously act to put obstacles into the option 1 and 2.

+ Closing Position:
    After partyA make their closing request requestToClosePosition everything is in the hands of partyB of that specific position.
    If partyB don't call fillCloseRequest and close the position, partyA have no way to close the position without forcing. Let's look at forcing in this case:

    ```forceClosePosition```
```solidity
    function forceClosePosition(uint256 quoteId, PairUpnlAndPriceSig memory upnlSig) internal {
        AccountStorage.Layout storage accountLayout = AccountStorage.layout();
        MAStorage.Layout storage maLayout = MAStorage.layout();
        Quote storage quote = QuoteStorage.layout().quotes[quoteId];

        uint256 filledAmount = quote.quantityToClose;
        require(quote.quoteStatus == QuoteStatus.CLOSE_PENDING, "PartyAFacet: Invalid state");
        require(
            block.timestamp > quote.modifyTimestamp + maLayout.forceCloseCooldown,
            "PartyAFacet: Cooldown not reached"
        );
...
```
As we can see, to forceClosePosition, partyA needs to wait until maLayout.forceCloseCooldown amount of time has passed. Which is set to (3000000000000000) in default. Which is practically impossible. But even if this cooldown changes, it won't solve the problem because again it might be too late to get rid of liquidation.

+ Opening hedge position
    In order to neutralize their upcoming upnl's, partyA might decide opening new position via sendQuote. But here is the catch:
    Malicious partyB can lock this quote and refuse to open the position. If this happens, partyA will obviously want to call requestToCancelQuote which again the outcome is completely in the hands of partyB who is malicious in our case. If they want to force it, they again need to wait until the cooldown pass. Again even if the protocol reduce the cooldown to reasonable time, it doesn't change the fact that partyB has all the control and partyA can be liquidated during this cooldown time.

Although you might think that then this malicious behaviour gets punished, it actually won't happen because partyB has do nothing wrong in this scenario, he/she act according to his/her rights and it seems completely ok to the protocol to lock quotes without opening it, and prevent closing positions with this manner.
Although whitelisting partyB's while sending quote might solve this issue, since this is not the default action in sendQuote we can obviously assume that this scenario is more than likely considering liquidations of partyA, leads to gain for partyB's.

## Impact
PartyB's have too many privileges and can use them maliciously without doing anything malicious according to protocol. Using these privileges partyB's can prevent their partyA's new actions and forcefully liquidate them if they are on the dangerous zone (close to liquidation) in order to make profit.

## Recommendations
I would like to especially point out that this issue can not be solved by just changing forceCloseCooldown parameter. In markets everything can happen so fast and even choosing 1 hour period for this parameter again does not prevent malicious partyB's to reach their goals. One possible solution to this situation:

+ Letting other partyB's than quote's partyB to be able to fillCloseRequest. Of course this might not go well with protocols main goals but it can be implemented such that both partyB make profit via this action. It will be better than partyA's force liquidations.
+ But of course this problem might require more brainstorming between protocols developers, and I don't think there is an easy solution that won't hurt anyone. But we can safely say that solutions won't hurt as much as current status.

## <a id='M-02'></a>M-02. System can get into a state where user actions are paused while liquidations not          


## Summary

It is possible to unfairly liquidate a user because user can not allocate any value to their positions because of pausing states.

## Vulnerability Details

In order to avoid going into liquidation (for any party) user's can:

+ close their positions(1)
+ deposit and allocate new funds to their positions(2)
+ open hedge positions with some other party(3).

However, it is very possible that users will not be able to use any of these solutions because of pausing states.
While there are too many scenarios that this situation can happen (because of too many pausing states) let's consider the easiest one:

1. PartyA has very negative upnl and will go into liquidation if won't do anything.
2. PartyA doesn't have any free balance to open new positions hence solution number 1 and 3 is impossible, only way is solution 2.
3. Accounting is paused hence partyA can not deposit and allocate funds to avoid liquidation.
4. Liquidations are not paused, hence after some time partyA gets liquidated.

There are of course multiple scenarios that this situation can occur. For example If partyA actions are paused then even if partyA has allocated free balance, solution 1 and 3 won't work. Same is true for partyB as well.

## Impact

Users can not prevent their liquidation in certain pausing states hence get liquidated unfairly.

## Recommendations

Never put system into a state where repayments are paused and liquidations are enabled. Require that in order to put system into any of these situations:
-Accounting Paused
-PartyA Actions Paused
-PartyB Actions Paused
Liquidations must be first paused.

## <a id='M-03'></a>M-03. User account and its funds got stuck in liquidation phase


## Summary

If liquidator starts the liquidation process but not continue within possible timeframe (before liquidationTimeout has passed) user account will stuck in liquidation position with its funds locked. This is true for both partyA and partyB.

## Vulnerability Details

Liquidation occurs with multiple functions (4 with partyA and 2 with partyB). Let's start with partyA's liquidation process.
First, liquidator calls liquidatePartyA providing a signature and partyA address, and states that this address is insolvent with this uPNL at this timestamp.
```solidity
    function liquidatePartyA(address partyA, SingleUpnlSig memory upnlSig) internal {
        MAStorage.Layout storage maLayout = MAStorage.layout();

        LibMuon.verifyPartyAUpnl(upnlSig, partyA);
        int256 availableBalance = LibAccount.partyAAvailableBalanceForLiquidation(
            upnlSig.upnl,
            partyA
        );
        require(availableBalance < 0, "LiquidationFacet: PartyA is solvent");
        maLayout.liquidationStatus[partyA] = true;
        maLayout.liquidationTimestamp[partyA] = upnlSig.timestamp;
        AccountStorage.layout().liquidators[partyA].push(msg.sender);
    }
```
As can be seen from the function, user account will be flagged as liquidateable and at this stage, the user account is frozen. Also at this stage ```maLayout.liquidationTimestamp[partyA]``` has been set to the ```upnlSig.timestamp```. When partyA's liquidation status is true, partyA literally can not do anything with their positions (e.g. can not close their position and get their money back), and can not open any positions.
That means right now the account is completely frozen with it funds and only way to unlock is through liquidators. Only way to make liquidation statues of partyA to false is in function liquidatePositionsPartyA.
In here we can see that after liquidation process is done, the status will set back to false:
```solidity
maLayout.liquidationStatus[partyA] = false;
```
In order to call this function, liquidator first needs to call ```setSymbolsPrice``` function as can be seen with this require state:
```solidity
require(
                accountLayout.symbolsPrices[partyA][quote.symbolId].timestamp ==
                    maLayout.liquidationTimestamp[partyA],
                "LiquidationFacet: Price should be set"
            );
```
So far it seems good because that was the required steps to liquidate partyA, but the problem comes in setSymbolsPrice() function. Here we can see that this function can only be called after liquidatePartyA() called and timestamp set, and before liquidationTimeout passed:
```solidity
 require(
            priceSig.timestamp <=
                maLayout.liquidationTimestamp[partyA] + maLayout.liquidationTimeout,
            "LiquidationFacet: Expired signature"
        );
```
(For extra information, liquidationTimeout automatically set to the 600 seconds in ControlFacet.sol)
That means if liquidator don't call setSymbolsPrice function before required time (600 seconds in default) it won't be callable again ever and also all other functions regarding partyA will be locked because liquidationStatus stucked at true. Hence account will be frozen with its positions and funds.
Same situation occurs for partyB too. Although there are only two functions to liquidate PartyB, again liquidatePartyB locks partyB's situation to true and again set liquidationtimestamp. In the second function liquidatePositionsPartyB we have liquidationTimeout check and if this fails it's not possible to convert the liquidationStatus of PartyB against PartyA to false. Code for partyB:
```solidity
maLayout.partyBLiquidationStatus[partyB][partyA] = true;
maLayout.partyBLiquidationTimestamp[partyB][partyA] = upnlSig.timestamp;
```
```solidity
require(
            priceSig.timestamp <=
                maLayout.partyBLiquidationTimestamp[partyB][partyA] + maLayout.liquidationTimeout,
            "LiquidationFacet: Expired signature"
        );
...
if (quoteLayout.partyBPositionsCount[partyB][partyA] == 0) {
            maLayout.partyBLiquidationStatus[partyB][partyA] = false;
            maLayout.partyBLiquidationTimestamp[partyB][partyA] = 0;
```
## Impact

Account is frozen with all its positions and funds, and it's not recoverable. Hence both partyA and partyB is losing all of their funds regarding to these positions.

## Recommendations

One possible solution is:
You can make it possible such that if user is not liquidated within given timeframe, liquidation status of user's account set to false again in order for other liquidators to start liquidation process again.

