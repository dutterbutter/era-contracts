import { Command } from "commander";
import { Wallet, ethers } from "ethers";
import { Deployer } from "../src.ts/deploy";
import { formatUnits, parseUnits } from "ethers/lib/utils";
import { web3Provider, getNumberFromEnv, REQUIRED_L2_GAS_PRICE_PER_PUBDATA } from "./utils";
import {
  L2_WETH_BRIDGE_IMPLEMENTATION_BYTECODE,
  L2_WETH_BRIDGE_PROXY_BYTECODE,
  L2_WETH_PROXY_BYTECODE,
  L2_WETH_IMPLEMENTATION_BYTECODE,
} from "./utils-bytecode";

import * as fs from "fs";
import * as path from "path";

const provider = web3Provider();
const testConfigPath = path.join(process.env.ZKSYNC_HOME as string, "etc/test_config/constant");
const ethTestConfig = JSON.parse(fs.readFileSync(`${testConfigPath}/eth.json`, { encoding: "utf-8" }));

const DEPLOY_L2_BRIDGE_COUNTERPART_GAS_LIMIT = getNumberFromEnv("CONTRACTS_DEPLOY_L2_BRIDGE_COUNTERPART_GAS_LIMIT");

async function main() {
  const program = new Command();

  program.version("0.1.0").name("initialize-weth-bridges-chain");

  program
    .option("--private-key <private-key>")
    .option("--chain-id <chain-id>")
    .option("--gas-price <gas-price>")
    .option("--nonce <nonce>")
    .action(async (cmd) => {
      const chainId: string = cmd.chainId ? cmd.chainId : process.env.CHAIN_ETH_ZKSYNC_NETWORK_ID;
      const deployWallet = cmd.privateKey
        ? new Wallet(cmd.privateKey, provider)
        : Wallet.fromMnemonic(
            process.env.MNEMONIC ? process.env.MNEMONIC : ethTestConfig.mnemonic,
            "m/44'/60'/0'/0/0"
          ).connect(provider);
      console.log(`Using deployer wallet: ${deployWallet.address}`);

      const gasPrice = cmd.gasPrice ? parseUnits(cmd.gasPrice, "gwei") : await provider.getGasPrice();
      console.log(`Using gas price: ${formatUnits(gasPrice, "gwei")} gwei`);

      const nonce = cmd.nonce ? parseInt(cmd.nonce) : await deployWallet.getTransactionCount();
      console.log(`Using deployer nonce: ${nonce}`);

      const deployer = new Deployer({
        deployWallet,
        verbose: true,
      });

      const bridgehub = deployer.bridgehubContract(deployWallet);
      const l1WethBridge = deployer.defaultWethBridge(deployWallet);

      // There will be two deployments done during the initial initialization
      const requiredValueToInitializeBridge = await bridgehub.l2TransactionBaseCost(
        chainId,
        gasPrice,
        DEPLOY_L2_BRIDGE_COUNTERPART_GAS_LIMIT,
        REQUIRED_L2_GAS_PRICE_PER_PUBDATA
      );

      const priorityTxMaxGasLimit = getNumberFromEnv("CONTRACTS_PRIORITY_TX_MAX_GAS_LIMIT");

      const requiredValueToPublishBytecodes = await bridgehub.l2TransactionBaseCost(
        chainId,
        gasPrice,
        priorityTxMaxGasLimit,
        REQUIRED_L2_GAS_PRICE_PER_PUBDATA
      );

      const independentInitialization = [
        bridgehub.requestL2Transaction(
          chainId,
          ethers.constants.AddressZero,
          0,
          "0x",
          priorityTxMaxGasLimit,
          REQUIRED_L2_GAS_PRICE_PER_PUBDATA,
          [L2_WETH_PROXY_BYTECODE, L2_WETH_IMPLEMENTATION_BYTECODE],
          deployWallet.address,
          { gasPrice, nonce, value: requiredValueToPublishBytecodes }
        ),
        l1WethBridge.startInitializeChain(
          chainId,
          [L2_WETH_BRIDGE_IMPLEMENTATION_BYTECODE, L2_WETH_BRIDGE_PROXY_BYTECODE],
          requiredValueToInitializeBridge,
          requiredValueToInitializeBridge,
          {
            gasPrice,
            nonce: nonce + 1,
            value: requiredValueToInitializeBridge.mul(2),
          }
        ),
      ];

      const txs = await Promise.all(independentInitialization);
      for (const tx of txs) {
        console.log(`Transaction sent with hash ${tx.hash} and nonce ${tx.nonce}. Waiting for receipt...`);
      }
      const receipts = await Promise.all(txs.map((tx) => tx.wait(2)));

      console.log(`WETH bridge priority tx sent to hyperchain, gasUsed: ${receipts[1].gasUsed.toString()}`);
      console.log(`WETH bridge initialized for chain ${chainId}, gasUsed: ${receipts[1].gasUsed.toString()}`);

      console.log(`CONTRACTS_L2_WETH_BRIDGE_ADDR=${await l1WethBridge.l2Bridge()}`);
    });

  await program.parseAsync(process.argv);
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error("Error:", err);
    process.exit(1);
  });
