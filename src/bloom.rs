
use ::xoodoo_hash::xoodoo_hash::{xoodoo_state::{XoodooStateNC}, XoodooHash};

#[derive(Debug)]
pub struct Bloom1X {
    /// number of hashes
    k: usize,
    /// number of rows in filter
    l: usize,
    /// width of row in bytes
    w: usize,
    /// number of bits to be extracted from hash for computing the row index
    row_bits: usize,
    /// number of bits to be extracted from hash for each sub-hash
    hash_bits: usize,
    /// memory representation of filter
    filter: Box<[Box<[u8]>]>
}

/// contains the info of a query given a hash digest
#[derive(Debug, Clone)]
pub struct QueryResult {
    /// gets the index where the bit is found inside a row
    bit_indexes: Vec<usize>,
    /// gets the row index inside the filter
    row_index: usize,
    /// gets the bitwise and result between the bits
    pub and_result: u8
}

impl Bloom1X {
    /// a filter represents a 2D array 
    /// w -> size of a row
    /// l -> number of rows
    /// h -> size of hash function output in bits
    pub fn new(k: usize, l: usize, w: usize, h:usize) -> Self {
        //some decent numbers should be provided
        assert!(w >= 32 && w % 8 == 0 && w <= 256);
        assert!(l >= 1024 && (l & (l - 1)) == 0 && l < u32::MAX as usize);
        assert!(k >= 2);
        assert!(h > 64);

        //number of bits needed to get a row inside the filter
        let row_bits = l.checked_ilog2().unwrap() as usize;
        assert!(row_bits < h);
        assert!((h - row_bits) % k == 0);
        let hash_bits = (h - row_bits) / k;

        let mut filter = vec![];
        for _ in 0..l {
            let row = vec![0 as u8; w/8];
            filter.push(row.into_boxed_slice());
        }
        let filter =filter.into_boxed_slice();
        Self { k, l, w, row_bits, hash_bits, filter }
    }

    pub fn clear(&mut self) {
        for i in 0..self.l {
            for j in 0..self.w/8 {
                self.filter[i][j] = 0;
            }
        }
    }

    /// the query functions check if a provided key is member of the filter
    /// returns 0x1 if the provided bytes were found inside the filter and 0x0 otherwise
    pub fn query_bytes(&self, bytes: &[u8]) -> u8 {
        assert!(bytes.len() * 8 <= 96); //can query keys of maximum 96-bits size
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_bytes(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        let query_result = self.parse_hash(&digest);
        query_result.and_result
    }

    /// returns 0x1 if the provided u32 was found inside the filter and 0x0 otherwise
    pub fn query_u32(&self, bytes: u32) -> u8 {
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_u32(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        let query_result = self.parse_hash(&digest);
        query_result.and_result
    }

    /// returns 0x1 if the provided u64 was found inside the filter and 0x0 otherwise
    pub fn query_u64(&self, bytes: u64) -> u8 {
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_u64(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        let query_result = self.parse_hash(&digest);
        query_result.and_result
    }

     pub fn query_bytes_with_result(&self, bytes: &[u8]) -> QueryResult {
        assert!(bytes.len() * 8 <= 96); //can query keys of maximum 96-bits size
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_bytes(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        let query_result = self.parse_hash(&digest);
        query_result
    }

    pub fn query_u64_with_result(&self, bytes: u64) -> QueryResult {
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_u64(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        let query_result = self.parse_hash(&digest);
        query_result
    }

    // given an older query result, check the current and_result again
    pub fn query_by_result(&self, qr: &QueryResult) -> u8 {
        let row = &self.filter[qr.row_index];
        let mut and_result: u8 = 1;
        for i in 0..self.k {
            let bit_index = qr.bit_indexes[i];
            let byte = row[bit_index/8];
            let bit = (byte >> (bit_index % 8)) & 0x1;
            and_result &= bit;   
        }
        and_result
    }

    /// given a digest obtained from the hash function, outputs the query info
    #[inline(always)]
    fn parse_hash(&self, digest: &[u32; 3]) -> QueryResult {
        let row_index = (digest[2] >> (32 - self.row_bits)) as usize; 
        let high_bits = digest[2] << self.row_bits;

        let digest:u128 = digest[0] as u128 | ((digest[1] as u128) << 32) | (high_bits as u128) << (64 - self.row_bits);
        let row = &self.filter[row_index];

        let mut bit_indexes= vec![];
        let mut and_result: u8 = 1;
        for i in 0..self.k {
            let bit_index = (digest >> (i * self.hash_bits)) as usize % self.w;
            let byte = row[bit_index/8];
            let bit = (byte >> (bit_index % 8)) & 0x1;
            bit_indexes.push(bit_index);
            and_result &= bit;   
        }
        QueryResult { bit_indexes, row_index, and_result }
    }

    /// given a query result, update the filter
    #[inline(always)]
    pub fn update_filter(&mut self, qr: &QueryResult) {
        let row = &mut self.filter[qr.row_index];
        for i in 0..self.k {
            let bit_index = qr.bit_indexes[i];
            let mut byte = row[bit_index/8];
            byte |= 1 << (bit_index % 8);
            row[bit_index/8] = byte;
        }
    }

    /// this functions queris the memebership returning the true/false response
    /// and also updates the filter with the new bits 
    pub fn query_and_set_bytes(&mut self, bytes: &[u8]) -> u8 {
        assert!(bytes.len() * 8 <= 96); //can query keys of maximum 96-bits size
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_bytes(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        let query_result = self.parse_hash(&digest);
        let result = query_result.and_result;
        self.update_filter(&query_result);
        result
    }

    pub fn query_and_set_u32(&mut self, bytes: u32) -> u8 {
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_u32(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        let query_result = self.parse_hash(&digest);
        let result = query_result.and_result;
        self.update_filter(&query_result);
        result    
    }

    pub fn query_and_set_u64(&mut self, bytes: u64) -> u8 {
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_u64(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        let query_result = self.parse_hash(&digest);
        let result = query_result.and_result;
        self.update_filter(&query_result);
        result   
    }
}