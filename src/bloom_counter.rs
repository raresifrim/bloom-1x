
use ::xoodoo_hash::xoodoo_hash::{xoodoo_state::{XoodooStateNC}, XoodooHash};

#[derive(Debug)]
pub struct Bloom1Counter {
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
pub struct CounterResult {
    /// gets the index where the counter is found inside a row
    pub(crate) counter_indexes: Vec<usize>,
    /// gets the value of each counter
    pub(crate) counters: Vec<u8>,
    /// gets the row index inside the filter
    pub(crate) row_index: usize,
    /// gets the cummulated result of all queried counters
    pub and_result: u8
}

impl Bloom1Counter {
    /// a filter represents a 2D array 
    /// w -> size of a row (number of counters/row)
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
            let row = vec![0 as u8; w];
            filter.push(row.into_boxed_slice());
        }
        let filter =filter.into_boxed_slice();
        Self { k, l, w, row_bits, hash_bits, filter }
    }

    pub fn clear(&mut self) {
        for i in 0..self.l {
            for j in 0..self.w {
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

     pub fn query_bytes_with_result(&self, bytes: &[u8]) -> CounterResult {
        assert!(bytes.len() * 8 <= 96); //can query keys of maximum 96-bits size
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_bytes(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        let query_result = self.parse_hash(&digest);
        query_result
    }

    pub fn query_u64_with_result(&self, bytes: u64) -> CounterResult {
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_u64(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        let query_result = self.parse_hash(&digest);
        query_result
    }

    // given an older query result, check the current and_result again
    pub fn query_by_result(&self, qr: &CounterResult) -> u8 {
        let row = &self.filter[qr.row_index];
        let mut and_result: u8 = 1;
        for i in 0..self.k {
            let counter_index = qr.counter_indexes[i];
            let counter = row[counter_index];
            if counter == 0 {
                and_result = 0;
                break;
            }
        }
        and_result
    }

    //given a u64, search its position in the filter and return the row index and counter indexes for all sub-hashes
    pub fn search_u64(&self, bytes: u64) -> CounterResult {
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_u64(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();

        let row_index = (digest[2] >> (32 - self.row_bits)) as usize; 
        let high_bits = digest[2] << self.row_bits;

        let digest:u128 = digest[0] as u128 | ((digest[1] as u128) << 32) | (high_bits as u128) << (64 - self.row_bits);

        let mut counter_indexes= vec![];
        for i in 0..self.k {
            let counter_index = (digest >> (i * self.hash_bits)) as usize % self.w;
            counter_indexes.push(counter_index); 
        }
        
        CounterResult { counter_indexes, row_index, and_result:0, counters:vec![]}
    }

    pub(crate) fn get_counters_u32(&self, bytes: u32) -> CounterResult{
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_u32(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        self.parse_hash(&digest)
    }

    pub(crate) fn get_counters_u64(&self, bytes: u64) -> CounterResult{
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_u64(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        self.parse_hash(&digest)
    }

    //given an array of bytes, search their position in the filter and return the row index and bit indexes for all sub-hashes
    pub fn search_bytes(&self, bytes: &[u8]) -> CounterResult {
        assert!(bytes.len() * 8 <= 96); //can query keys of maximum 96-bits size
        
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_bytes(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        
        let row_index = (digest[2] >> (32 - self.row_bits)) as usize; 
        let high_bits = digest[2] << self.row_bits;

        let digest:u128 = digest[0] as u128 | ((digest[1] as u128) << 32) | (high_bits as u128) << (64 - self.row_bits);

        let mut counter_indexes= vec![];
        for i in 0..self.k {
            let bit_index = (digest >> (i * self.hash_bits)) as usize % self.w;
            counter_indexes.push(bit_index); 
        }
        
        CounterResult { counter_indexes, row_index, and_result:0, counters: vec![]}
    }

    /// given a digest obtained from the hash function, outputs the query info
    #[inline(always)]
    fn parse_hash(&self, digest: &[u32; 3]) -> CounterResult {
        let row_index = (digest[2] >> (32 - self.row_bits)) as usize; 
        let high_bits = digest[2] << self.row_bits;

        let digest:u128 = digest[0] as u128 | ((digest[1] as u128) << 32) | (high_bits as u128) << (64 - self.row_bits);
        let row = &self.filter[row_index];

        let mut counter_indexes= vec![];
        let mut counters= vec![];
        let mut and_result: u8 = 1;
        for i in 0..self.k {
            let counter_index = (digest >> (i * self.hash_bits)) as usize % self.w;
            let counter = row[counter_index];
            counter_indexes.push(counter_index);
            counters.push(counter);
            if counter == 0 {
                and_result = 0;
            }
        }
        CounterResult { counter_indexes, row_index, and_result, counters }
    }

    /// given a query result, update the filter
    #[inline(always)]
    pub fn inc_counters(&mut self, qr: &CounterResult) {
        let row = &mut self.filter[qr.row_index];
        for i in 0..self.k {
            let counter_index = qr.counter_indexes[i];
            let counter = row[counter_index];
            row[counter_index] = counter.wrapping_add(1);
        }
    }

     /// given a query result, update the filter
    #[inline(always)]
    pub fn dec_counters(&mut self, qr: &CounterResult) {
        let row = &mut self.filter[qr.row_index];
        for i in 0..self.k {
            let counter_index = qr.counter_indexes[i];
            let counter = row[counter_index];
            row[counter_index] = counter.wrapping_sub(1);
        }
    }

    /// these functions queries the memebership returning the true/false response
    /// and also increments the counters of the filters
    pub fn query_and_inc_bytes(&mut self, bytes: &[u8]) -> u8 {
        assert!(bytes.len() * 8 <= 96); //can query keys of maximum 96-bits size
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_bytes(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        let query_result = self.parse_hash(&digest);
        let result = query_result.and_result;
        self.inc_counters(&query_result);
        result
    }

    pub fn query_and_inc_u32(&mut self, bytes: u32) -> u8 {
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_u32(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        let query_result = self.parse_hash(&digest);
        let result = query_result.and_result;
        self.inc_counters(&query_result);
        result    
    }

    pub fn query_and_inc_u64(&mut self, bytes: u64) -> u8 {
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_u64(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        let query_result = self.parse_hash(&digest);
        let result = query_result.and_result;
        self.inc_counters(&query_result);
        result   
    }

    /// these functions queries the memebership returning the true/false response
    /// and also decrements the counters of the filters
    pub fn query_and_dec_bytes(&mut self, bytes: &[u8]) -> u8 {
        assert!(bytes.len() * 8 <= 96); //can query keys of maximum 96-bits size
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_bytes(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        let query_result = self.parse_hash(&digest);
        let result = query_result.and_result;
        self.dec_counters(&query_result);
        result
    }

    pub fn query_and_dec_u32(&mut self, bytes: u32) -> u8 {
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_u32(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        let query_result = self.parse_hash(&digest);
        let result = query_result.and_result;
        self.dec_counters(&query_result);
        result    
    }

    pub fn query_and_dec_u64(&mut self, bytes: u64) -> u8 {
        let mut hasher = XoodooHash::<XoodooStateNC>::new_from_u64(bytes);
        hasher.permute_nc();
        let digest = hasher.digest_nc();
        let query_result = self.parse_hash(&digest);
        let result = query_result.and_result;
        self.dec_counters(&query_result);
        result   
    }
}