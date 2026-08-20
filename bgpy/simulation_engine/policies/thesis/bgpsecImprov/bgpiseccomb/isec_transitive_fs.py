from typing import TYPE_CHECKING, Any

from bgpy.simulation_engine.policies.bgp import BGP
from bgpy.simulation_engine.policies.thesis.bgpisecCrypt import BGPiSecCryptTransitive

if TYPE_CHECKING:
    from bgpy.as_graphs import AS
    from bgpy.enums import Relationships
    from bgpy.simulation_engine.announcement import Announcement as Ann

import hashlib


class FSBGPiSecCryptTransitive(BGPiSecCryptTransitive):
    """
    Represents BGPiSec Transitive attributes"
    using FSBGP signatures process for testing (will probably not work using transitive signatures, especially for lower adoption rates)
    -> When multiple nonadoption ASes chain after one another Part shortening attacks will become viable again
    """

    name = "FSBGP-iSec Crypt Transitive Only "


    #################
    # Signing funcs #
    #################

    def create_ann_hash(
        self,
        prefix: str,
        next_asn: int,
        path: tuple[int, ...] | None = None,
        signatures: tuple[tuple[int, bytes], ...] | None = None, ### int (asn of signing as) only gets added bc its easier to debug. Can be subject to change TODO: Remove
    ) -> bytes:
        """
        Critical Path Segments to sign over:
        si =
            {a1 a0 f}a0 for i =0
            {ai+1 ai ai-1}ai for 0 <i ≤ n
        """
        if(path is None):
            pref_path = (next_asn, self.as_.asn, prefix) 
            pref_hash_tuple = (prefix, pref_path)
            hashed_update = hashlib.sha256(string=str(pref_hash_tuple).encode(), usedforsecurity=True).digest()
        elif(len(path) == 1):
            pref_path = (next_asn, path[0], prefix) 
            pref_hash_tuple = (prefix, pref_path)
            hashed_update = hashlib.sha256(string=str(pref_hash_tuple).encode(), usedforsecurity=True).digest()       
        else:
            ### path should consist of (ai, ai-1, ai-2, ...); self.as_.asn replacable by path[0]
            fullhash_path = (next_asn, path[0], path[1]) 

            ## Here ,if the previous AS is also adopting, their Sig is signed over as well. This can be changed but could partially help in partial adoption?
            if(signatures is not None and signatures[0][0] == path[1]):        
                sig_hash_tuple = (prefix, fullhash_path, signatures[0][1])                 
                hashed_update = hashlib.sha256(string=str(sig_hash_tuple).encode(), usedforsecurity=True).digest()
            else:
                hash_tuple = (prefix, fullhash_path)
                hashed_update = hashlib.sha256(string=str(hash_tuple).encode(), usedforsecurity=True).digest()

        return hashed_update