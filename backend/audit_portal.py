from flask import Flask, jsonify
from web3 import Web3

app = Flask(__name__)

# Connect to blockchain
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
contract_address = "0xYourContractAddress"
abi = [
    # Paste your smart contract ABI here
]
contract = w3.eth.contract(address=contract_address, abi=abi)

# Route to get all candidates and their vote counts
@app.route('/audit', methods=['GET'])
def audit():
    total_candidates = contract.functions.totalCandidates().call()
    candidates = []
    for i in range(1, total_candidates + 1):
        candidate = contract.functions.candidates(i).call()
        candidates.append({
            "id": candidate[0],
            "name": candidate[1],
            "voteCount": candidate[2]
        })
    return jsonify(candidates)

if __name__ == "__main__":
    app.run(debug=True)
