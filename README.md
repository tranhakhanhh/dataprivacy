# Evaluate the runtime and accuracy of multiple approaches used to maintain data privacy

This program compares the runtime and accuracy of the following 4 approaches in calculating the average of n values from n parties:
1. No privacy
2. Paillier Encryption Scheme
3. Secure Multi-Party Computation (SMPC)
4. Differential Privacy (DP)


## Files

main.py: Calculate the average of n integers using 4 approaches and generate runtime and accuracy analysis

runtime.png: Graph of runtime analysis

accuracy.png: Graph of accuracy analysis

## Installation

Use a package manager to install matplotlib and phe.

```bash
pip install matplotlib
pip install phe
```

## Terminal instructions
To run the code

```python
python main.py
```
