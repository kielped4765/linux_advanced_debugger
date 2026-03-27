#include <iostream>

void foo() {
    std::cout << "foo" << std::endl;
}

void bar() {
    foo();
}

int main() {
    bar();
}
