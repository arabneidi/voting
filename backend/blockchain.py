import hashlib
import json
from time import time
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

# Define SQLAlchemy instance to be used with blockchain
db = SQLAlchemy()

class Block:
    def __init__(self, index, timestamp, data, previous_hash=''):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def to_dict(self):
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash,
            'hash': self.hash
        }

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []

    def create_genesis_block(self):
        return Block(0, time(), "Genesis Block", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, block):
        self.chain.append(block)

    def add_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self):
        # Mine the pending transactions into a block
        new_block = Block(len(self.chain), time(), self.pending_transactions, self.get_latest_block().hash)
        self.add_block(new_block)
        self.pending_transactions = []

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Validate the block hash
            if current_block.hash != current_block.calculate_hash():
                return False

            # Validate the previous block hash link
            if current_block.previous_hash != previous_block.hash:
                return False

        return True

    # Save blockchain block to the database
    def save_block_to_db(self, new_block):
        block_data = {
            'block_index': new_block.index,
            'timestamp': datetime.fromtimestamp(new_block.timestamp),  # Convert UNIX time to MySQL datetime format
            'user_id': new_block.data['user_id'],
            'candidate_id': new_block.data['candidate_id'],
            'encrypted_vote': new_block.data['encrypted_vote'],
            'previous_hash': new_block.previous_hash,
            'block_hash': new_block.hash
        }
        # Create and insert new BlockchainModel instance to save in DB
        blockchain_entry = BlockchainModel(
            block_index=block_data['block_index'],
            timestamp=block_data['timestamp'],
            user_id=block_data['user_id'],
            candidate_id=block_data['candidate_id'],
            encrypted_vote=block_data['encrypted_vote'],
            previous_hash=block_data['previous_hash'],
            block_hash=block_data['block_hash']
        )
        db.session.add(blockchain_entry)
        db.session.commit()

# BlockchainModel to represent the database table
class BlockchainModel(db.Model):
    __tablename__ = 'blockchain'

    id = db.Column(db.Integer, primary_key=True)
    block_index = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    candidate_id = db.Column(db.Integer, nullable=False)
    encrypted_vote = db.Column(db.String(500), nullable=False)
    previous_hash = db.Column(db.String(64), nullable=False)
    block_hash = db.Column(db.String(64), nullable=False)

    def __init__(self, block_index, timestamp, user_id, candidate_id, encrypted_vote, previous_hash, block_hash):
        self.block_index = block_index
        self.timestamp = timestamp
        self.user_id = user_id
        self.candidate_id = candidate_id
        self.encrypted_vote = encrypted_vote
        self.previous_hash = previous_hash
        self.block_hash = block_hash
