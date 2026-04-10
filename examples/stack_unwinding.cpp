#include <iostream>

__attribute__((noinline)) void foo(int x) {
    std::cout << "foo: " << x << std::endl;
}

__attribute__((noinline)) void bar() {
    // Force a stack frame by allocating a local array
    volatile int dummy[64]; 
    dummy[0] = 42;
    
    foo(dummy[0]);
    
    // Force the compiler to come back here
    std::cout << "back in bar, value is " << dummy[0] << std::endl;
}

int main() {
    volatile int a = 42;
    std::cout << a << std::endl;
}