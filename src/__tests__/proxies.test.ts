import { expect, describe, test } from "vitest";

import { cached_test, online_test, makeProvider } from "./env";

import { abiFromBytecode, disasm } from "../disasm";
import { addSlotOffset, readArray, joinSlot } from "../slots.js";
import * as proxies from "../proxies";

import { ZEPPELINOS_USDC, WANDERWING } from "./__fixtures__/proxies";
import { whatsabi } from "../index";
import { decodeFunctionData, padHex } from "viem";

// TODO: Test for proxy factories to not match

describe("proxy detection", () => {
  test("Minimal Proxy Pattern", async () => {
    // https://eips.ethereum.org/EIPS/eip-1167
    // includes deploy instructions
    const bytecode = "0x3d602d80600a3d3981f3363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe5af43d82803e903d91602b57fd5bf3";

    const program = disasm(bytecode);
    expect(program.proxies[0]).toBeInstanceOf(proxies.FixedProxyResolver);
    const proxy = program.proxies[0] as proxies.FixedProxyResolver;
    expect(proxy.resolvedAddress).toBe("0xbebebebebebebebebebebebebebebebebebebebe");
    expect(proxy.name).toBe("FixedProxy");
    expect(proxy.toString()).toBe("FixedProxy");
  });

  test("EIP-1167 Proxy: Uniswap v1", async () => {
    // const address = "0x09cabec1ead1c0ba254b09efb3ee13841712be14";
    const bytecode = "0x3660006000376110006000366000732157a7894439191e520825fe9399ab8655e0f7085af41558576110006000f3";
    const want = "0x2157a7894439191e520825fe9399ab8655e0f708";
    const program = disasm(bytecode);
    expect(program.proxies[0]).toBeInstanceOf(proxies.FixedProxyResolver);
    const proxy = program.proxies[0] as proxies.FixedProxyResolver;
    expect(proxy.resolvedAddress).toBe(want);
  });

  test("Solady Minimal Proxy: CWIA", async () => {
    // https://github.com/Vectorized/solady/blob/main/src/utils/LibClone.sol
    const bytecode =
      "0x36602c57343d527f9e4ac34f21c619cefc926c8bd93b54bf5a39c7ab2127a895af1cc0691d7e3dff593da1005b363d3d373d3d3d3d610016806062363936013d73bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb5af43d3d93803e606057fd5bf3e127ce638293fa123be79c25782a5652581db2340016";
    const program = disasm(bytecode);
    expect(program.proxies[0]).toBeInstanceOf(proxies.FixedProxyResolver);
    const proxy = program.proxies[0] as proxies.FixedProxyResolver;
    const want = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    expect(proxy.resolvedAddress).toBe(want);
  });

  test("SequenceWallet Proxy", async () => {
    // Gas-optimized version of EIP-1167
    // https://github.com/0xsequence/wallet-contracts/blob/master/contracts/Wallet.sol
    const bytecode = "0x363d3d373d3d3d363d30545af43d82803e903d91601857fd5bf3";
    const program = disasm(bytecode);
    expect(program.proxies[0]).toBeInstanceOf(proxies.SequenceWalletProxyResolver);
  });

  test("Gnosis Safe Proxy Factory", async () => {
    // https://eips.ethereum.org/EIPS/eip-1167
    const bytecode =
      "0x608060405273ffffffffffffffffffffffffffffffffffffffff600054167fa619486e0000000000000000000000000000000000000000000000000000000060003514156050578060005260206000f35b3660008037600080366000845af43d6000803e60008114156070573d6000fd5b3d6000f3fea265627a7a72315820d8a00dc4fe6bf675a9d7416fc2d00bb3433362aa8186b750f76c4027269667ff64736f6c634300050e0032";

    const program = disasm(bytecode);
    expect(program.proxies[0]).toBeInstanceOf(proxies.GnosisSafeProxyResolver);
    expect(program.proxies[0].name).toBe("GnosisSafeProxy");
  });

  test("ZeppelinOS Proxy", async () => {
    const bytecode = ZEPPELINOS_USDC;
    const program = disasm(bytecode);
    expect(program.proxies[0]).toBeInstanceOf(proxies.ZeppelinOSProxyResolver);
  });

  // TODO: Make this work
  test.skip("EIP-1967 Proxy: Wanderwing", async () => {
    const bytecode = WANDERWING;
    const program = disasm(bytecode);
    expect(program.proxies[0]).toBeInstanceOf(proxies.EIP1967ProxyResolver);
  });
});

describe("known proxy resolving", () => {
  online_test("Safe: Proxy Factory 1.1.1", async ({ provider }) => {
    const address = "0x655a9e6b044d6b62f393f9990ec3ea877e966e18";
    // Need to call masterCopy() or getStorageAt for 0th slot
    const resolver = new proxies.GnosisSafeProxyResolver();
    const got = await resolver.resolve(provider, address);
    const want = "0x34cfac646f301356faa8b21e94227e3583fe3f5f";
    expect(got).toEqual(want);
  });

  online_test("EIP-1967 Proxy: Aztec TransparentUpgradeableProxy", async ({ provider }) => {
    const address = "0xff1f2b4adb9df6fc8eafecdcbf96a2b351680455";
    const resolver = new proxies.EIP1967ProxyResolver();
    const got = await resolver.resolve(provider, address);
    const wantImplementation = "0x7d657ddcf7e2a5fd118dc8a6ddc3dc308adc2728";

    expect(got).toEqual(wantImplementation);
  });

  online_test("EIP-1967 Proxy: NFTX", async ({ provider }) => {
    const address = "0x3E135c3E981fAe3383A5aE0d323860a34CfAB893";
    const resolver = new proxies.EIP1967ProxyResolver();
    const got = await resolver.resolve(provider, address);
    const wantImplementation = "0xccb1cfc9caa2b73a82ad23a9b3219da900485880";

    expect(got).toEqual(wantImplementation);
  });

  online_test("EIP-2535 Diamond Proxy: ZkSync Era", async ({ provider }) => {
    // More diamond proxies, if we need sometime: https://gist.github.com/banteg/74fa02c5457f2141bba11dd431fc2b57

    const address = "0x32400084C286CF3E17e7B677ea9583e60a000324";
    const resolver = new proxies.DiamondProxyResolver();
    const selector = "0x6e9960c3"; // function getAdmin() returns (address)
    const got = await resolver.resolve(provider, address, selector);

    // ZkSync updates their proxies so it's annoying to maintain the desired mapping
    expect(got).not.toEqual("0x0000000000000000000000000000000000000000");
  });

  online_test("EIP-2535 Diamond Proxy: Read facets from internal storage", async ({ provider }) => {
    const address = "0x32400084C286CF3E17e7B677ea9583e60a000324";
    const resolver = new proxies.DiamondProxyResolver();
    const got = await resolver.selectors(provider, address);

    expect(got).to.not.equal([]);
  });

  // FIXME: Is there one on mainnet? Seems they're all on polygon
  //online_test('SequenceWallet Proxy', async() => {
  //});

  cached_test("LayerrProxy on Sepolia", async ({ withCache }) => {
    // For issue #139: https://github.com/shazow/whatsabi/issues/139
    const provider = makeProvider("https://ethereum-sepolia-rpc.publicnode.com");
    const address = "0x2f4eeccbe817e2b9f66e8123387aa81bae08dfec";
    const code = await withCache(`${address}_code`, async () => {
      return await provider.getCode(address);
    });

    const program = disasm(code);
    const resolver = program.proxies[0];
    const got = await resolver.resolve(provider, address);
    const wantImplementation = "0x0000000000f7a60f1c88f317f369e3d8679c6689";

    expect(got).toEqual(wantImplementation);
  });
});

describe("contract proxy resolving", () => {
  cached_test("Create2Beacon Proxy", async ({ provider, withCache }) => {
    const address = "0x581acd618ba7ef6d3585242423867adc09e8ed60";
    const code = await withCache(`${address}_code`, async () => {
      return await provider.getCode(address);
    });

    const program = disasm(code);
    expect(program.proxies.length).toEqual(1);

    const resolver = program.proxies[0];
    const got = await resolver.resolve(provider, address);

    const wantImplementation = "0xaddc3e67a500f7037cd622b11df291a6351bfb64";
    expect(got).toEqual(wantImplementation);
  });

  cached_test("Vyper Minimal Proxy", async ({ provider, withCache }) => {
    const address = "0x2d5d4869381c4fce34789bc1d38acce747e295ae";
    const code = await withCache(`${address}_code`, async () => {
      return await provider.getCode(address);
    });

    const program = disasm(code);
    expect(program.proxies.length).toEqual(1);

    const resolver = program.proxies[0];
    const got = await resolver.resolve(provider, address);

    const wantImplementation = "0x9c13e225ae007731caa49fd17a41379ab1a489f4";
    expect(got).toEqual(wantImplementation);
  });
});

describe("proxy internal slot reading", () => {
  test("addSlotOffset", async () => {
    const slot = "0xc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131b";
    const got = addSlotOffset(slot, 2);

    expect(got).to.equal("0xc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131d");
  });

  test("joinSlot", async () => {
    const got = joinSlot(["0xf3acf6a03ea4a914b78ec788624b25cec37c14a4", "0xc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c"]);
    const want = "0x42983d3cf213719a972df53d14775d9ca74cc01b862f850a60cf959f26ffe0a2";
    expect(got).toEqual(want);
  });

  online_test("ReadArray: Addresses and Selectors", async ({ provider }) => {
    const address = "0x32400084C286CF3E17e7B677ea9583e60a000324";
    const facetsOffset = addSlotOffset(proxies.slots.DIAMOND_STORAGE, 2); // Facets live in the 3rd slot (0-indexed)

    const addressWidth = 20; // Addresses are 20 bytes
    const facets = await readArray(provider, address, facetsOffset, addressWidth);
    expect(facets.length).to.not.equal(0);

    // Read selectors
    const storageStart = addSlotOffset(proxies.slots.DIAMOND_STORAGE, 1); // facetToSelector in 2nd slot
    const facetAddress = "0x" + facets[0];
    const facetToSelectorSlot = joinSlot([facetAddress, storageStart]);
    const selectorWidth = 4;
    const got = await readArray(provider, address, facetToSelectorSlot, selectorWidth);
    expect(got.length).to.not.equal(0);
  });
});

describe("multiple proxy resolving", () => {
  cached_test("resolve WeightedRateSetCollectionPool", async ({ withCache, provider }) => {
    const address = "0x56C5Aef1296d004707475c8440f540DdA409b53D";
    const code = await withCache(`${address}_code`, async () => {
      return await provider.getCode(address);
    });
    const program = disasm(code);

    expect(program.proxies.length).to.be.equal(4);
  });
});

describe("comprehensive proxy detection", () => {
  const diamondProxies = [
    "0x32400084c286cf3e17e7b677ea9583e60a000324",
    "0x3caca7b48d0573d793d3b0279b5f0029180e83b6",
    "0xc1e088fc1323b20bcbee9bd1b9fc9546db5624c5",
    "0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae",
    "0x1c073d5045b1abb6924d5f0f8b2f667b1653a4c3",
    "0xe21ebcd28d37a67757b9bc7b290f4c4928a430b1",
    "0x226bf5293692610692e2c996c9875c914d2a7f73",
    "0x07f4d0691ee248b46fb71afa15f28a08d951a002",
    "0xd57474e76c9ebecc01b65a1494f0a1211df7bcd8",
  ];

  diamondProxies.map((address) => {
    cached_test("DiamondProxy: " + address, async ({ withCache, provider }) => {
      const address = "0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae";
      const code = await withCache(`${address}_code`, async () => {
        return await provider.getCode(address);
      });
      const program = disasm(code);
      expect(program.proxies.length).toEqual(1);
      const resolver = program.proxies[0];
      expect(resolver.name).toEqual("DiamondProxy");

      const facets = await (resolver as proxies.DiamondProxyResolver).facets(provider, address, { limit: 1 });
      expect(facets).to.not.be.empty;
    });
  });

  cached_test("DiamondProxy: LiFi on Base", async ({ withCache }) => {
    // For issue #139: https://github.com/shazow/whatsabi/issues/139
    const provider = makeProvider("https://base-rpc.publicnode.com");
    const address = "0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae";
    const code = await withCache(`base-${address}_code`, async () => {
      return await provider.getCode(address);
    });

    const program = disasm(code);
    expect(program.proxies.length).toEqual(1);
    const resolver = program.proxies[0];
    expect(resolver.name).toEqual("DiamondProxy");

    const code2 =
      "0x60806040523661000b57005b600080357fffffffff000000000000000000000000000000000000000000000000000000001681527fc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c6020819052604090912054819073ffffffffffffffffffffffffffffffffffffffff16806100ae576040517fa9ad62f800000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b3660008037600080366000845af43d6000803e8080156100cd573d6000f35b3d6000fd5b7fc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c132080547fffffffffffffffffffffffff0000000000000000000000000000000000000000811673ffffffffffffffffffffffffffffffffffffffff8481169182179093556040517fc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c939092169182907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e090600090a3505050565b60005b83518110156103225760008482815181106101ac576101ac611129565b6020026020010151602001519050600060028111156101cd576101cd611158565b8160028111156101df576101df611158565b0361022d576102288583815181106101f9576101f9611129565b60200260200101516000015186848151811061021757610217611129565b602002602001015160400151610387565b610319565b600181600281111561024157610241611158565b0361028a5761022885838151811061025b5761025b611129565b60200260200101516000015186848151811061027957610279611129565b602002602001015160400151610627565b600281600281111561029e5761029e611158565b036102e7576102288583815181106102b8576102b8611129565b6020026020010151600001518684815181106102d6576102d6611129565b6020026020010151604001516108d0565b6040517fe548e6b500000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5060010161018f565b507f8faa70878671ccd212d20771b795c50af8fd3ff6cf27f4bde57e5d4de0aeb673838383604051610356939291906111f5565b60405180910390a16103688282610a0c565b505050565b73ffffffffffffffffffffffffffffffffffffffff161590565b80516000036103c2576040517f7bc5595000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b7fc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c73ffffffffffffffffffffffffffffffffffffffff8316610430576040517fc68ec83a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b73ffffffffffffffffffffffffffffffffffffffff83166000908152600182016020526040812054906bffffffffffffffffffffffff82169003610478576104788285610bad565b60005b835181101561062057600084828151811061049857610498611129565b6020908102919091018101517fffffffff00000000000000000000000000000000000000000000000000000000811660009081529186905260409091205490915073ffffffffffffffffffffffffffffffffffffffff168015610527576040517fa023275d00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b7fffffffff000000000000000000000000000000000000000000000000000000008216600081815260208781526040808320805473ffffffffffffffffffffffffffffffffffffffff908116740100000000000000000000000000000000000000006bffffffffffffffffffffffff8c16021782558c168085526001808c0185529285208054938401815585528385206008840401805463ffffffff60079095166004026101000a948502191660e08a901c94909402939093179092559390925287905281547fffffffffffffffffffffffff00000000000000000000000000000000000000001617905550506001918201910161047b565b5050505050565b8051600003610662576040517f7bc5595000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b7fc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c73ffffffffffffffffffffffffffffffffffffffff83166106d0576040517fc68ec83a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b73ffffffffffffffffffffffffffffffffffffffff83166000908152600182016020526040812054906bffffffffffffffffffffffff82169003610718576107188285610bad565b60005b835181101561062057600084828151811061073857610738611129565b6020908102919091018101517fffffffff00000000000000000000000000000000000000000000000000000000811660009081529186905260409091205490915073ffffffffffffffffffffffffffffffffffffffff90811690871681036107cc576040517fa023275d00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6107d7858284610c23565b7fffffffff000000000000000000000000000000000000000000000000000000008216600081815260208781526040808320805473ffffffffffffffffffffffffffffffffffffffff908116740100000000000000000000000000000000000000006bffffffffffffffffffffffff8c16021782558c168085526001808c0185529285208054938401815585528385206008840401805463ffffffff60079095166004026101000a948502191660e08a901c94909402939093179092559390925287905281547fffffffffffffffffffffffff00000000000000000000000000000000000000001617905550506001918201910161071b565b805160000361090b576040517f7bc5595000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b7fc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c73ffffffffffffffffffffffffffffffffffffffff83161561097a576040517f79c9df2200000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b60005b8251811015610a0657600083828151811061099a5761099a611129565b6020908102919091018101517fffffffff00000000000000000000000000000000000000000000000000000000811660009081529185905260409091205490915073ffffffffffffffffffffffffffffffffffffffff166109fc848284610c23565b505060010161097d565b50505050565b73ffffffffffffffffffffffffffffffffffffffff8216610a6457805115610a60576040517f9811686000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5050565b8051600003610a9f576040517f4220056600000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b73ffffffffffffffffffffffffffffffffffffffff82163014610ac557610ac5826110ec565b6000808373ffffffffffffffffffffffffffffffffffffffff1683604051610aed919061135d565b600060405180830381855af49150503d8060008114610b28576040519150601f19603f3d011682016040523d82523d6000602084013e610b2d565b606091505b509150915081610a0657805115610b7b57806040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610b729190611379565b60405180910390fd5b6040517fc53ebed500000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b610bb6816110ec565b60028201805473ffffffffffffffffffffffffffffffffffffffff90921660008181526001948501602090815260408220860185905594840183559182529290200180547fffffffffffffffffffffffff0000000000000000000000000000000000000000169091179055565b73ffffffffffffffffffffffffffffffffffffffff8216610c70576040517fa9ad62f800000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b3073ffffffffffffffffffffffffffffffffffffffff831603610cbf576040517fc3c5ec3700000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b7fffffffff0000000000000000000000000000000000000000000000000000000081166000908152602084815260408083205473ffffffffffffffffffffffffffffffffffffffff86168452600180880190935290832054740100000000000000000000000000000000000000009091046bffffffffffffffffffffffff169291610d4991611393565b9050808214610e905773ffffffffffffffffffffffffffffffffffffffff841660009081526001860160205260408120805483908110610d8b57610d8b611129565b6000918252602080832060088304015473ffffffffffffffffffffffffffffffffffffffff8916845260018a019091526040909220805460079092166004026101000a90920460e01b925082919085908110610de957610de9611129565b600091825260208083206008830401805463ffffffff60079094166004026101000a938402191660e09590951c929092029390931790557fffffffff0000000000000000000000000000000000000000000000000000000092909216825286905260409020805473ffffffffffffffffffffffffffffffffffffffff16740100000000000000000000000000000000000000006bffffffffffffffffffffffff8516021790555b73ffffffffffffffffffffffffffffffffffffffff841660009081526001860160205260409020805480610ec657610ec66113d3565b6000828152602080822060087fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff90940193840401805463ffffffff600460078716026101000a0219169055919092557fffffffff000000000000000000000000000000000000000000000000000000008516825286905260408120819055819003610620576002850154600090610f5f90600190611393565b73ffffffffffffffffffffffffffffffffffffffff8616600090815260018089016020526040909120015490915080821461104d576000876002018381548110610fab57610fab611129565b60009182526020909120015460028901805473ffffffffffffffffffffffffffffffffffffffff9092169250829184908110610fe957610fe9611129565b600091825260208083209190910180547fffffffffffffffffffffffff00000000000000000000000000000000000000001673ffffffffffffffffffffffffffffffffffffffff948516179055929091168152600189810190925260409020018190555b86600201805480611060576110606113d3565b6000828152602080822083017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff90810180547fffffffffffffffffffffffff000000000000000000000000000000000000000016905590920190925573ffffffffffffffffffffffffffffffffffffffff88168252600189810190915260408220015550505050505050565b803b6000819003610a60576040517fe350060000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b60005b838110156111a257818101518382015260200161118a565b50506000910152565b600081518084526111c3816020860160208601611187565b601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0169290920160200192915050565b60006060808301818452808751808352608092508286019150828160051b8701016020808b0160005b84811015611320577fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff808a8503018652815188850173ffffffffffffffffffffffffffffffffffffffff825116865284820151600381106112a7577f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b868601526040918201519186018a905281519081905290840190600090898701905b8083101561130b5783517fffffffff000000000000000000000000000000000000000000000000000000001682529286019260019290920191908601906112c9565b5097850197955050509082019060010161121e565b505073ffffffffffffffffffffffffffffffffffffffff8a1690880152868103604088015261134f81896111ab565b9a9950505050505050505050565b6000825161136f818460208701611187565b9190910192915050565b60208152600061138c6020830";
    const program2 = disasm(code2);
    console.log("program2", program2);

    const selector = "0x736eac0b";
    const got = await resolver.resolve(provider, address, selector);
    expect(got).not.toEqual("0x0000000000000000000000000000000000000000");
  });

  online_test("DiamondProxy: LiFi on Base online", async ({}) => {
    // For issue #139: https://github.com/shazow/whatsabi/issues/139
    const provider = makeProvider("https://base-rpc.publicnode.com");
    const address = "0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae";
    const code = await provider.getCode(address);

    const program = disasm(code);
    expect(program.proxies.length).toEqual(1);
    const resolver = program.proxies[0];
    expect(resolver.name).toEqual("DiamondProxy");

    const selector = "0x736eac0b";
    const implementation = await resolver.resolve(provider, address, selector);

    console.log("implementation", implementation);
    expect(implementation).not.toEqual("0x0000000000000000000000000000000000000000");
    const abiLoader = await new whatsabi.loaders.BlockscoutABILoader();
    const abi = await abiLoader.loadABI(implementation);
    console.log("abi", abi);

    expect(abi.length).not.toEqual(0);
  });
});
