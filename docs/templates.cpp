#include <iostream>
#include <vector>
using namespace std;


namespace function_templates{
// 1. this is how you write a function template.
// the compiler doesn't compile this function as is.
// if the compiler sees a caller calling func1 with int, then it
// replaces every instance of T with int and then compiles.
// NOTE: not quite obvious, T should be *copyable*

template<typename T>
T func1(T a, T b){
    return (a < b) ? a : b;
}


void caller1(){
    auto u = func1(3, 4);
    auto v = func1<int>(4, 5); // can also specify explicity what the function template is.
}


// 2. both of these functions are doing the same thing. you cannot access T inside print2 (maybe using shenanigans)

template<typename T>
void print1(T x){
    for(const auto& t: x)
        cout << t << " ";
}


auto print2(const auto& x){
    for(const auto& u: x)
        cout << u << " ";
}


void caller2(){
    print1({1, 2, 3});
    print2<vector<int>>({1, 2, 3}); // print2 behaves like a function template even though we used auto, you can specify types.
}


// 3. NOTE: as mentioned earlier, templates don't give you a way of knowing what the parameters are.
// for example, for func1, T must be copyable/movable. for print1, x must be iterable.
// enter concepts.
}


// CONCEPTS:
// formulates formal constraints for generic code.
// they act as boolean predicates evaluated at compile time to restrict the types or values that a template can accept.

// general rule: concept Name = {COMPILE TIME boolean expression}

// REQUIRES keyword:
// there are 4 types of usages
namespace requires_keyword{
// NOTE: 1. Simple Requirements: checks if an expression compiles
// whatever's in the scope of requires should compile. if everything in the scope compiles, it returns true
// returns false if it doesn't compile. you can have how many ever statements/"declarations of T" you want.
/*
 * it checks *validity*, *not runtime behavior*
 * it checks syntax, NOT logical correctness
 * return types are ignored by default in simple requirements:
 *      if you just call x.size(), it returns true if x.size() compiles, doesn't care if it returns void, string etc.
*/
template<typename T>
concept SimpleRq = requires(T x) {
    cout << x;
};

template<typename T>
concept SimpleRq2 = requires(T x, T y) {
    x + y;
    x - y;
    x++;
    y--;
    cout << x;
    cin >> y;
    x.size(); // doesn't care about the return type. if this compiles, it returns true.
};


// 2. Type requirements
// checks whether a specific type exists and is accessible.
// typename {}; -> if this compiles, we're good.
template<typename T>
concept TypeRq = requires {
    typename T::something; // requires T to define something.

    // SIMPLE REQUIREMENT:
    // Checks if 'T::asdf' is a valid EXPRESSION (e.g., accessing a static variable).
    T::asdf;

    // TYPE REQUIREMENT:
    // Checks if 'T::jkl' is a valid TYPE name.
    typename T::jkl;
};


template<typename C>
    requires TypeRq<C>
void some_func(C arg){
    // safe to use C::value_type here because the concept guarantees it exists
    using jkl = C::jkl;

    if(!arg.empty()){
        jkl val = *arg.begin();
        auto t = C::asdf;
        std::cout << val << t << '\n';
    }
}


// NOTE: 3. Compound requirements
/*
    { expression } noexcept -> ConstraintConcept<Args...>;
    expression: compulsory, the expression to be evaluated inside curly braces.
    noexcept: optional
    ContraintConcept: compulsory, specifies a concept that the return type of the expression must satisfy.
*/
/*
    you cannot write it like this: { x.getValue() } -> int;
    you have to do this: { x.getValue() } -> std::same_as<int>;
*/
// If expr has type R, writing { expr } -> Concept<Args...> is equivalent to checking if Concept<R, Args...> is true.
template<typename T>
concept CompRq = requires(T a, T b) {
    { a == b } noexcept -> std::convertible_to<bool>;
    { swap(a, b) } noexcept; // no -> concept, just checks if swap(a,b) is non-throwing.
};

template<typename T>
concept CustomConstraintConcept = (sizeof(T) == 4); // see 4, can be written with nested requires.

template<typename T>
concept CompRq2 = requires(T a) {
    a++;
    { a.size() } -> CustomConstraintConcept; // evaluates internally as: requires CustomConstraintConcept< (typeof a.size())>;
};

template<typename T, typename U>
concept CCC2 = requires(T a, T b, U c) {
    a + b >= c;
};

template<typename T>
concept CompRq3 = requires(T a) {
    { a.size() } -> CCC2<int>; // evaluates internally as: requires CCC2<(typeof a.size()), int>;
};


// NOTE: 4. nested requirements
template<typename T>
concept NestedRq = requires {
    requires std::integral<T>;
    requires CompRq3<T>;
    requires sizeof(T) <= 4; // RIGHT: does (sizeof(T) <= 4) return true?
    sizeof(T) <= 4;          // WRONG: does the line "sizeof(T) <= 4" compile?
};
}


namespace extra_stuff_about_require{
// NOTE: 1
// don't write shit like this:
template<typename T>
    requires requires(T a) { { a.size() } -> std::convertible_to<int>; }
int bad_function(T x){
    return x.size();
}


// first requires: the actual requires for the function
// second requires: the concept which is required by the function.
template<typename T>
concept Sizeable = requires(T a) {
    { a.size() } -> std::convertible_to<int>;
};


template<typename T>
    requires Sizeable<T>
int good_function(T x){
    return x.size();
}


// NOTE: 2
// instead of writing
template<typename T>
    requires Sizeable<t>
int some_func(T x){
    return x.size();
}


// we can directly write it like
template<Sizeable T> // note: Sizeable T
int somez_func(T x){
    return x.size();
}


// NOTE: 3
// concept ConceptName = RHS. here are a list of all the RHS possible.

// 1. requires
template<typename T>
concept Rhs1 = requires {
    typename T::something;
};

// 2. existing concepts
template<typename T>
concept Rhs2 = Sizeable<T>;

// 3. logical operators
template<typename T>
concept Rhs3 = Sizeable<T> && std::integral<T>;
template<typename T>
concept Rhs4 = std::integral<T> && requires(T a) { a++; };

// 4. compile-time arithmetic/comparisons.
template<typename T>
concept Rhs5 = sizeof(T) == 4 && sizeof(T) == sizeof(void*);

// 5. custom constexpr variable templates or constexpr functions that return a bool.
// variable template
template<typename T>
constexpr bool is_custom_valid_v = sizeof(T) % 2 == 0;

// constexpr function
constexpr bool asdf(){
    return true;
}


template<typename T>
concept Rhs6 = is_custom_valid_v<T> && asdf();


// NOTE: 4
// syntax for template functions 1
template<typename T>
    requires Rhs2<T>
T asdf1(T x, T y){
    return (x < y) ? x : y;
}


// syntax for template functions 2
template<typename T>
T asdf2(T x, T y) requires Rhs2<T>{
    return (x < y) ? x : y;
}
}


namespace multiple_template_arguments{
template<typename T1, typename T2>
void multiple_template_func(T1 x, T2 y){}


/*
template <typename T1, typename T2>
?? mymax(T1 x, T2 y){
    return (x<y)?x:y;
}
*/

template<typename T1, typename T2>
auto mymax(T1 x, T2 y){
    return (x < y) ? x : y;
}


// BUG: this doesn't compile, auto cannot deduce one single type to return, auto fails.
template<typename T1, typename T2>
auto evil_func(T1 x, T2 y, int z){
    if(z == 69){
        return x;
    }
    return y;
}
}


namespace class_template{
template<typename T>
class U{
    // you can use T here. as normal.
};


template<typename T>
class Stack{
public:
    void push();


    void pop();


    T top();


    void print(){
        for(auto& t: impl){
            cout << t << " ";
        }
        cout << endl;
    }

private:
    vector<T> impl;
};


// does this mean everything which uses stack should support the << operator?
// no: if your code doesn't use .print() (like your code never calls Stack<MyClass>.print(), it will work fine.
// CONDITIONAL COMPILING.
}


namespace non_type_template_arguments{
template<typename T, int size> // notice size is not a "typename" / "class".
class buffer{
public:
    T arr[size];
};


void do_something(){
    buffer<int, 5> buf;
}


// non-type template arguments (NTTP) allows us to pass values, rather than types at compile time.
// before c++20: we could use: ints, bools, chars, enums, POINTERS AND REFERENCES TO *STATIC* (or global) OBJECTS as NTTPs
// after c++20: float, double and this:
/*
    Classes and structs where:
        1. all non-static data members must be public and non-mutable. (mutable defined below)
        2. the types of all non-static data members must be structural types (or arrays) (like ints, pointers, enums etc)
        3. the class must be a literal type (must have at least one constexpr contructor)

    -> when a constructor is marked with constexpr, it allows for the object creation and initialization
        at compile time. if atleast one constructor is marked with constexpr, it becomes a "literal type".
        if you pass in runtime arguments to the constexpr contructor, it behaves like a normal constructor.

    struct Point{
        int x;
        int y;
        constexpr Point(x, y) : x{x}, y{y} {}
    };

    int main(){
        constexpr Point p1(5,3);  // evaluated entirely at compile time, notice "constexpr".

        int a = 4; int b = 3;
        Point p2(a,b);            // evaluated at runtime.
    }
*/

namespace mutable_keyword{
// by default, a const member function cannot modify any member variables of the class.
// marking a variable as mutable bypasses this restriction.
/*
    use cases:
        1. storing the result of an expensive calculation inside a const getter so it doesn't have to be recomputed next time.
        2. locks/mutexes to protect shit done by a const marked function
        3. statistics / counters. (no_of_times_called etc).
*/
/*
    important notes:
        1. cannot mark static members with mutable: "const" is defined for "one object" (const-guarantee for the
            specific object). static variables don't belong to "one object". CONST FUNCTIONS CAN ALREADY MODFIY STATIC VARS
        2. cannot mark const or reference (&) variables as mutable: idk
        3. overusing mutable breaks const correctness guarantees and can introduce hidden side effects or multi-threading bugs
*/

class DataFetcher{
private:
    std::string cached_data;
    static int dont_use_me;
    const int cant_increment_me = 0;
    int& can_increment_me;
    // mutable int& x;
    mutable int access_count = 0;

public:
    DataFetcher(std::string data, int& x):
        cached_data(data),
        can_increment_me(x){}


    std::string getData() const{
        access_count++; // allowed only because access_count is mutable
        dont_use_me++;
        // cant_increment_me++;
        can_increment_me++;
        return cached_data;
    }


    int getAccessCount() const{
        return access_count;
    }
};


// NOTE: mutable servers as something different in lambda fucntions.
void do_something(){
    int counter = 0;
    auto lambda1 = [counter](){
        counter++; // when counter is captured by value, it is maked as const by default. doesn't compile
    };
    auto lambda2 = [counter]() mutable{
        counter++;
    };

    lambda2(); // counter = 1;
    lambda2(); // counter = 2;
    lambda2(); // counter = 3;
}
}


struct Color{
    uint8_t r, g, b;
    // mutable uint8_t x; bug: can't have mutable here.

    constexpr Color(uint8_t red, uint8_t green, uint8_t blue):
        r(red),
        g(green),
        b(blue){}
};


// use it as an NTTP
template<Color ThemeColor>
class UIWindow{
public:
    void render(){
        // access ThemeColor.r, ThemeColor.g, ThemeColor.b at compile time
    }
};


UIWindow<Color{255, 0, 0}> redWindow;
}


namespace default_template_arguments{
// like regular function default arguments, if a template parameter has a default argument, all template parameters
// following it must also have default arguments

/* bug:
template <typename T = int, typename U, typename V = double>
class Broken;
*/
template<typename T, typename U = int, typename V = double>
class Correct;

// NOTE: 1
// Type Parameter Defaults
template<typename T = int>
class Box{
public:
    T value;
};


void do_something(){
    Box<> t; // nothing inside <>, defaulted to int.
    t.value = 4;
}


// NOTE: 2
// Non-Type Parameter Defaults
template<typename T, int U = 5>
class CustomArray{
    T data[U];
};


void do_nothing(){
    CustomArray<int> t;
    // t only has 5 elemlents
    CustomArray<int, 3> u;
}


// NOTE: Special
template<typename T, typename Allocator = std::allocator<T>> // can use T in allocator<T>.
class asdf{};
}


namespace template_specialization{
// NOTE: Full specialization
template<typename T>
class Something{
    void do_something(){
        cout << "Hello, I'm a default object of class something";
    }
};


// override, everything for bool is different.
template<> // nothing here.
class Something<bool>{
    // declared with bool.
    void do_something(){
        cout << "Hello, I'm bool object of class something";
    }
};


// NOTE: Partial specialization
template<typename T, typename U>
class Storage{};


template<typename T>
class Storage<T, int>{}; // fixes the second parameter as int

template<typename T>
class Storage<T, T>{}; // activates when both are of the same type.

// important: the compiler will evaluate constraints based on which template is a "better match".
template<typename T, typename U>
    requires requires(T t, U u) {
        t++;
        u--;
    }
class Storage<T, U>{};


template<typename T, typename U>
class Storage<T*, U*>{}; // compiler chooses this when T and U are pointer types.
/*
    if you use Storage<int*, double*> the compiler matches *T = int and U = double*, it chooses the partial specialization
    instead of the generic template because this is a stricter match.
*/


// important: for functions, we don't need to have <> after the function name for partial specialization.
template<typename T, typename U>
void do_something(T a, U b){}


template<typename T>
void do_something(T a, int b){} // not void do_something<T,int>(){}, use function overloading
}


namespace variable_templates{
template<typename T>
constexpr T pi = T(3.1415926535897932385L);

double d_pi = pi<double>;
float f_pi = pi<float>;
}


namespace dependent_names_and_disambiguation{
template<typename T>
void process(){
    // requires 'typename' because T::value_type depends on template parameter T
    typename T::value_type var;

    // requires 'template' keyword when calling a templated member function on a dependent type
    T obj;
    obj.template parse<int>();
}
}


namespace template_template_parameters{
template<typename T>
struct Vector{
    T data;
};

template<typename T, template<typename> class Container>
struct CustomContainer{
    Container<T> data;
};

CustomContainer<int, std::vector> cc1;
CustomContainer<int, Vector> cc2;
}


namespace variadic_templates_and_parameter_packs{
// ellipsis = ...
/*
    the ellipsis servers 3 purposes
        1. Variadic Templates & Parameter Packs (below)
        2. C-Style Variadic Functions (namespace ellipsis)
        3. Catch-All Exception Handlers (namespace ellipsis)
*/
namespace ellipsis{

namespace c_style_variadic_functions{
// because of legacy reasons, this still exists.
// use low-level c functions like va_list, va_arg to parse ... arguments
// in modern c++, always use templates if you want to use c-style variadic functions.
// there is no compiler safety too. just ignore this as much as possible
}

namespace catch_all{
void do_something(){
    try{
        // some dangerous code
    }
    catch(...){
        // all exceptions are captured here
    }
}

void do_nothing(){
    try{
        // some dangerous code
    }
    catch(const std::runtime_error& e){
        // runtime errors are caught here
    }
    catch(...){
        // all other exceptions are caught here
    }

}
}
}


// https://www.youtube.com/watch?v=zx4f7OT7Uec
/*
    1. we couldn't (with caveats) have an arbitarary number of template parameters before c++11
    2. there were some workarounds to this. (typelists)
*/

// todo: complete this


}
