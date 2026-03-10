from predict import run_prediction

# Test different inputs to show the model is working
test_inputs = [
    "execve brk mmap openat fstat",
    "pread64 mmap mmap mmap mmap mmap close mmap arch_prctl set_tid_address set_robust_list rseq mprotect mprotect mprotect mprotect prlimit64 munmap getrandom brk brk",
    "futex rt_sigaction futex close rt_sigaction futex getpid rt_sigaction exit_group",
]

print("Testing Malware Detection Model")
print("=" * 50)

for i, text in enumerate(test_inputs, 1):
    print(f"\nTest {i}:")
    print(f"Input: {text}")
    
    # Single prediction with probabilities
    result = run_prediction(text=text, proba=True)
    
    # Print the results
    for r in result:
        print(f"  Predicted Malware Type: {r['Predicted_Malware_Type']}")
        print(f"  Confidence: {r['Probability']:.3f}")
        print(f"  Top Predictions: {r['Top_Predictions']}")
    
    print("-" * 30)
