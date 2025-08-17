pub mod bloom;

#[cfg(test)]
mod tests {
    use crate::bloom::Bloom1X;

    #[test]
    fn filter_membership() {
        let mut bloom_filter = Bloom1X::new(4, u16::MAX as usize + 1, 96, 96);

        //generate first 2^16 numbers
        for i in 0..(u16::MAX as u32 + 1) {
            assert!(bloom_filter.query_and_set_u32(i) == 0);
        }

        //check filter for current members
        for i in 0..(u16::MAX as u32 + 1) {
            assert!(bloom_filter.query_u32(i) == 1);
        }

        //check next int outside filter
        assert!(bloom_filter.query_u32(u16::MAX as u32 + 1) == 0)
    }

    #[test]
    fn query_and_update() {
        let mut bloom_filter = Bloom1X::new(4, u16::MAX as usize + 1, 96, 96);

        //generate first 2^16 numbers
        for i in 0..(u16::MAX as u32 + 1) {
            assert!(bloom_filter.query_and_set_u32(i) == 0);
        }

        //check filter for current members
        let mut count = 0;
        for i in (u16::MAX as u32 + 1)..(2 * u16::MAX as u32) {
            let result= bloom_filter.query_u64_with_result(i as u64);
            count += result.and_result;
            bloom_filter.update_filter(&result);
            assert!(bloom_filter.query_u32(i) == 1);
        }

        println!("Number of false positives: {}", count);
    }

    #[test]
    fn false_positive_768kb_small() {
        let mut bloom_filter = Bloom1X::new(4, u16::MAX as usize + 1, 96, 96);

        //generate first 2^16 numbers
        for i in 0..(u16::MAX as u32 + 1) {
            assert!(bloom_filter.query_and_set_u32(i) == 0);
        }

        //check filter for next set of numbers
        let mut count = 0;
        for i in (u16::MAX as u32 + 1)..(2 * u16::MAX as u32) {
            count += bloom_filter.query_and_set_u32(i);
        }
        let k = 4.0;
        let m = 96.0 * u16::MAX as f64;
        let n = 2.0 * u16::MAX as f64;
        let p = f64::powf(1.0 - f64::exp(-k / (m / n)), k);

        println!(
            "False Positives in {} elements = {}",
            2 * u16::MAX as u32,
            count
        );
        println!(
            "False Positives rate = {}",
            count as f64 / (2.0 * u16::MAX as f64)
        );
        println!("Computed False Positive rate = {}", p);
    }

    #[test]
    fn false_positive_768kb_large() {
        let mut bloom_filter = Bloom1X::new(4, u16::MAX as usize + 1, 96, 96);

        let mut count: usize = 0;
        for i in 0..1_000_000 {
            count += bloom_filter.query_and_set_u64(i + 0xDEADBEEF) as usize;
        }

        for i in 1_000_000..2_000_000 {
            count += bloom_filter.query_and_set_u64(i + 0xDEADBEEF) as usize;
        }
        let k = 4.0;
        let m = 96.0 * u16::MAX as f64;
        let n = 2000000.0;
        let p = f64::powf(1.0 - f64::exp(-k / (m / n)), k);

        println!("False Positives in {} elements = {}", 2000000, count);
        println!("False Positives rate = {}", count as f64 / 2000000.0);
        println!("Computed False Positive rate = {}", p);
    }

    #[test]
    fn false_positive_36kb_small() {
        let mut bloom_filter = Bloom1X::new(2, 1024, 32, 96);

        let mut count: usize = 0;
        //test with 4000 elements
        for i in 0..4000 {
            count += bloom_filter.query_and_set_u32(i) as usize;
        }

        //check filter for next set of numbers
        for i in 4000..8000 {
            count += bloom_filter.query_and_set_u32(i) as usize;
        }

        println!(
            "False Positives in {} elements = {}",
            2 * u16::MAX as u32,
            count
        );
        println!(
            "False Positives rate = {}",
            count as f64 / (2.0 * u16::MAX as f64)
        );

        bloom_filter.clear();

        let mut count: usize = 0;
        //test with 4000 elements
        for i in 0..4000 {
            count += bloom_filter.query_and_set_u64(i + 0xDEADBEEF) as usize;
        }

        //check filter for next set of numbers
        for i in 4000..8000 {
            count += bloom_filter.query_and_set_u64(i + 0xDEADBEEF) as usize;
        }

        println!(
            "False Positives 2 in {} elements = {}",
            2 * u16::MAX as u32,
            count
        );
        println!(
            "False Positives 2 rate = {}",
            count as f64 / (2.0 * u16::MAX as f64)
        );

        let k = 2.0;
        let m = 36.0 * 1024.0; //FPGA BRAM block
        let n = 4000.0;
        let p = f64::powf(1.0 - f64::exp(-k / (m / n)), k);
        println!("Computed False Positive rate = {}", p);
    }

    #[test]
    fn query_by_result() {
         let mut bloom_filter = Bloom1X::new(4, u16::MAX as usize + 1, 96, 96);

        //generate first 2^16 numbers
        for i in 0..10000 {
            let qr = bloom_filter.query_u64_with_result(i as u64);
            assert!(qr.and_result == 0);
            bloom_filter.update_filter(&qr);
            let result = bloom_filter.query_by_result(&qr);
            assert!(result == 1);
        }

    }
}
