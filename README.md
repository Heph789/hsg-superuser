# Hats Signer Gate Super User

Hello! This repo contains a fork of [Hats Signer Gate](https://github.com/Hats-Protocol/hats-zodiac) to enable a hats-controlled multisig to be accountable to its admin hat(s). Currently this module is in early stages, so please use at your own risk. A DAO could potentially use these contracts to build on-chain committees:

- assign elected members signer roles through hats
- transfer the grants budget to the safe
- allow committee members to independently dole out funds
- allow the DAO to clawback funds if need be
- allow the DAO to veto malicious/bad/self-serving transactions from the committee
- allow the DAO to predefine restrictions through setting a Guard contract

The following contracts implement this functionality:

- HSGSuperMod
- HSGSuperFactory

## HSGSuperMod

This contract grants multisig signing rights to addresses wearing a given Hat, enabling on-chain organizations (such as DAOs) to revocably delegate constrained signing authority and responsibility to individuals, much like Hats Signer Gate, with some additional features: the owner ("Authority") hat can execute transactions on behalf of the safe (making it a “superuser”), and a special assignee (does not necessarily have to be a hats-wearer) can revoke safe transactions within an allotted period of time (the "Canceller"). The Authority can change who the Canceller is at any time, or add more than one Canceller. The Authority can also set a Guard contract, which enforces restrictions on the transactions being executed.

When an HSGSuperMod is deployed, it is deployed with a TimelockController attached. Signers must execute their transactions through a timelock controller by calling the `scheduleTransaction` function on HSGSuperMod. Once the sufficient time has passed, the signer can call `executeTimelockTransaction`. Within the "timelock" period, the defined canceller address can cancel this proposal. The Authority hat-wearer can change who this canceller is at any time through the `setCanceller` and `removeCanceller` functions. Additionally, the Authority can add a Zodiac guard that transactions must adhere to by using the `changeGuard` function. To remove the guard, the Authority must set the guard to `address(0)`.

Below is an overview of the normal HatsSignerGate which HSGSuperMod builds off.

### Overview

### Zodiac Module

[HatsSignerGate.sol](https://github.com/Heph789/hsg-superuser/blob/dev/src/HSGSuperMod.sol) is a **Zodiac module** that...

1. Grants multisig signing rights to addresses based on whether they are wearing the appropriate Hat(s).
2. Removes signers who are no long valid (i.e. no longer wearing the signer Hat)
3. Manages the multisig threshold within the [owner](#contract-ownership) specified range as new signers are added or removed.
4. Allows any admin/top hat to transfer value on behalf of the safe.
5. Sends transactions through a [TimelockController](https://docs.openzeppelin.com/contracts/4.x/api/governance#TimelockController), giving some assignee time to revoke transactions

### Zodiac Guard

Since Hat-wearing is dynamic — Hats can be programmatically revoked from wearers — this contract also services as a **Zodiac guard** to ensure that:

A) **Only valid signers can execute transactions**, i.e. only signatures made by accounts currently wearing a valid signer Hat count towards the threshold.

B) **Signers cannot execute transactions that remove the constraint in (A)**. Specifically, this contract guards against signers...

1. Removing the contract as a guard on the multisig
2. Removing the contract as a module on the multisig — or removing/changing/adding any other modules,
3. Changing the multisig threshold
4. Changing the multisig owners

> Warning
> Protections against (3) and (4) above only hold if the Safe does not have any authority over the signer Hat(s). If it does — e.g. it wears an admin Hat of the signer Hat(s) or is an eligibility or toggle module on the signer Hat(s) — then in some cases the signers may be able to change the multisig threshold or owners.
>
> Proceed with caution if granting such authority to a Safe attached to HatsSignerGate.

C) **Signers cannot execute transactions instantly.** All transactions must go through the TimelockController (and subsequently experience a delay) in order to execute.

### Contract Ownership

Hats Signer Gate uses the [HatsOwned](https://github.com/Hats-Protocol/hats-auth/) mix-in to manage ownership via a specified `ownerHat`.

The wearer of the `ownerHat` can make the following changes to Hats Signer Gate:

1. "Transfer" ownership to a new Hat by changing the `ownerHat`
2. Set the acceptable multisig threshold range by changing `minThreshold` and `targetThreshold`
3. Add other Zodiac modules to the multisig

> Note
> Although these permissions are granted to the wearer of a defined `ownerHat`, the “superuser” ability to execute transactions on the safe’s behalf is currently granted to **_any_** tophat of the `signerHat`. In the future, this may be different to match the `ownerHat` paradigm.

### HSGSuper Factory

[HSGSuperFactory](https://github.com/Heph789/hsg-superuser/blob/dev/src/HatsSignerGateFactory.sol) is a factory contract that enables users to deploy proxy instances of HSGSuperMod, either for an existing Safe or wired up to a new Safe deployed at the same time. It also deploys the corresponding TimelockController. It uses the [Zodiac module proxy factory](https://github.com/gnosis/zodiac/blob/master/contracts/factory/ModuleProxyFactory.sol) so that the deployments are tracked in the Zodiac subgraph.

### Deployments

#### Sepolia
**HSGSuperFactory:** ```0x2271ed6e83C155059150b8e3Ff684D46c1749906```

**Hats Contract:** ```0x3bc1A0Ad72417f2d411118085256fC53CBdDd137```

### Demos
https://youtu.be/byJVwVAAzq0

