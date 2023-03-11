from blockchain.block import Block
from blockchain import util
import config
from ecdsa import SigningKey


class PoABlock(Block):
    """ Extends Block, adding proof-of-work primitives. """

    def seal_is_valid(self):
        """ Checks whether a block's seal_data forms a valid seal.
            In PoA, this means that Verif(PK, [block, sig]) = accept.
            (aka the unsealed block header is validly signed under the authority's public key)

            Returns:
                bool: True only if a block's seal data forms a valid seal according to PoA.
        """
        if self.seal_data == 0:
            return False

        # Decode signature to bytes, verify it
        signature = hex(self.seal_data)[2:].zfill(96)
        return util.is_message_signed(self.unsealed_header(), signature, config.AUTHORITY_PK)

    def get_weight(self):
        """ All blocks have same weight in PoA """
        return 1

    def mine(self):
        """ PoA signer; seals a block with new seal data by signing it, checking that
            signature is valid, and returning.
        """

        # Use NIST192p curve and ECDSA, encoding block header as UTF-8
        # use self.get_private_key() for key
        # encode result as int and set using set_seal_data
        # make sure to check that output is valid seal with provided code
        # (if seal is invalid, repeat)

        while not self.seal_is_valid():
            pk = SigningKey.from_string(self.get_private_key())
            signature = pk.sign(self.unsealed_header().encode())
            self.set_seal_data(int.from_bytes(signature, 'big'))

    def calculate_appropriate_target(self):
        """ Target in PoA is currently meaningless """
        return 0

