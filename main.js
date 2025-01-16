const quais = require("quais");
const { HDNode, isValidMnemonic } = require("@quais/hdnode");
const fs = require("fs");
const Papa = require("papaparse");

const ADDRESSES_FILE = "addresses.csv";
const LIMIT = 1000;
const MAX_INDEX = 1000000000; // 1 billion
const COIN_TYPES = [1, 60, 994];

const SHARDS = [
  { shard: "cyprus-1", byte: ["00", "1D"] },
  { shard: "cyprus-2", byte: ["1E", "3A"] },
  { shard: "cyprus-3", byte: ["3B", "57"] },
  { shard: "paxos-1", byte: ["58", "73"] },
  { shard: "paxos-2", byte: ["74", "8F"] },
  { shard: "paxos-3", byte: ["90", "AB"] },
  { shard: "hydra-1", byte: ["AC", "C7"] },
  { shard: "hydra-2", byte: ["C8", "E3"] },
  { shard: "hydra-3", byte: ["E4", "FF"] },
];

// Read addresses.csv
const addressesData = fs.readFileSync(ADDRESSES_FILE, "utf8");
const { data } = Papa.parse(addressesData, { header: true });

// Addresses data is a single column with addresses. Read it as a set for efficient lookup
const addressesSet = new Set(data.map((row) => row.Address));

function printAddressTable(addresses, shard) {
  if (addresses.length === 0) {
    console.log(`No ${shard} addresses found`);
    return;
  }
  console.log(`\n${shard} addresses:`);
  const addressTable = addresses.map((addr) => ({
    PubKey: addr.pubKey,
    Address: addr.address,
    PrivateKey: addr.privateKey,
    Index: addr.index,
    CoinType: addr.coinType,
    Change: "No",
    Zone: addr.zone,
  }));
  console.table(addressTable);
}

function getShardFromAddress(address) {
  const shardData = SHARDS.find((obj) => {
    const num = Number(address.substring(0, 4));
    const start = Number("0x" + obj.byte[0]);
    const end = Number("0x" + obj.byte[1]);
    return num >= start && num <= end;
  });
  if (!shardData) {
    throw new Error("Invalid address");
  }
  return shardData.shard;
}

async function main() {
  // Check if a seed phrase is provided as a command line argument
  if (process.argv.length < 3) {
    console.error(
      "Please provide your iron age spanish seed phrase as a command line argument"
    );
    process.exit(1);
  }

  const seedPhrase = process.argv[2].trim();

  // Verify if the provided string is a valid mnemonic
  if (!isValidMnemonic(seedPhrase, quais.wordlists.es)) {
    process.exit(1);
  }

  console.log(
    `\nThis script will derive ${
      LIMIT * COIN_TYPES.length * 9
    } addresses across 9 shards. This can take several minutes to complete.\nExiting the process will cancel the operation.`
  );

  try {
    const quaiWallet = HDNode.fromMnemonic(seedPhrase, "", quais.wordlists.es);

    for (const coinType of COIN_TYPES) {
      console.log(`\nChecking addresses for coinType ${coinType}`);
      const shardAddresses = {
        "cyprus-1": [],
        "cyprus-2": [],
        "cyprus-3": [],
        "paxos-1": [],
        "paxos-2": [],
        "paxos-3": [],
        "hydra-1": [],
        "hydra-2": [],
        "hydra-3": [],
      };

      let allAddressesDerivedInAllShards = false;
      let index = 0;

      while (!allAddressesDerivedInAllShards && index < MAX_INDEX) {
        const childNode = quaiWallet.derivePath(
          `m/44'/${coinType}'/0'/0/${index}`
        );
        const wallet = new quais.Wallet(childNode.privateKey);
        const address = wallet.address;

        const shardFromAddress = getShardFromAddress(address);
        if (shardAddresses[shardFromAddress].length < LIMIT) {
          shardAddresses[shardFromAddress].push({
            pubKey: childNode.publicKey,
            address,
            privateKey: childNode.privateKey,
            index: index,
            zone: shardFromAddress,
            coinType: coinType,
          });
        } else {
          allAddressesDerivedInAllShards = Object.values(shardAddresses).every(
            (shard) => shard.length === LIMIT
          );
        }
        index++;
      }

      // Check if any of the derived addresses are in the addressesSet
      for (const shard of Object.keys(shardAddresses)) {
        printAddressTable(
          shardAddresses[shard].filter((addr) =>
            addressesSet.has(addr.address)
          ),
          shard
        );
      }
    }
  } catch (error) {
    console.error("Error computing address:", error.message);
    process.exit(1);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
