# blockchain_vote.py
from web3 import Web3

# Connect to local Ethereum network (or any deployed network)
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))  # Use your network provider

# ABI and contract address
contract_address = "0xYourContractAddress"
abi = [
    # Paste your smart contract ABI here (from Truffle or Remix)
]

# Interacting with the contract
contract = w3.eth.contract(address=contract_address, abi=abi)
account = w3.eth.accounts[0]  # Replace with the user's account

# Function to vote for a candidate
def cast_vote(candidate_id):
    tx_hash = contract.functions.vote(candidate_id).transact({'from': account})
    w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"Vote cast for candidate {candidate_id}")

# Get vote count for a candidate
def get_vote_count(candidate_id):
    votes = contract.functions.getVoteCount(candidate_id).call()
    print(f"Candidate {candidate_id} has {votes} votes")
    return votes

# Example usage
if __name__ == "__main__":
    candidate_id = 1  # Example candidate
    cast_vote(candidate_id)
    get_vote_count(candidate_id)
