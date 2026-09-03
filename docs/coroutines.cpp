#include <iostream>
#include <string>
#include <coroutine>
#include <thread>


/*

Introduction:

Regular function calls:
Caller -> function call -> function ends -> goes back to caller

Coroutines:
Caller -> coroutine call -> coroutine executes until co_yield or co_return ->
caller -> calls coroutine -> coroutine starts executing from where it left off (from co_yeild)
* A coroutine must always return a user-defined "wrapper" type (often called a Generator) that contains
* a nested promise_type

small example:

using dont_worry_about_me_right_now = std::generator<int>;
using dwamrn = dont_worry_about_me_right_now;

dwamrn coroutine_ex(){
    std::cout << "Hello! Doing some work here, produced the value 10!" << std::endl;
    co_yield 10;

    std::cout << "Doing some work again, produced the value 20!" << std::endl;
    co_yield 20;

    std::cout << "Doing some work for the last time, produced the value 30!" << std::endl;
    co_yield 30;
}

int main1(){
    // NOT ACTUAL CODE, JUST EXPLAINING
    auto gen = coroutine_ex();
    auto it = gen.begin();
    auto end = gen.end();

    while(it != gen.begin()){
        int num = *it;
        std::cout << "Coroutine produced the value: " << num << std::endl;
        it++;   // resumes the execution of coroutine_ex();
    }
}

? USING custom generator
int main2(){
    // NOT ACTUAL CODE, JUST EXPLAINING
    auto gen = coroutine_ex();

    while(!gen.done()){
        gen.continue_exec();
        int num = gen.get_value();
        std::cout << "Coroutine produced the value: " << num << std::endl;
    }
}




1. The heap state (Coroutine stack frame)

When a function contains co_yield (or co_await or co_return), it stops being a regular stack-based function,
because whenever a regular function exits, its stack gets rewinded. Since coroutines need a "state" to resume
from previous co_yields, we store the coroutines data in heap. this is stored:

+---------------------------------------------------------------+
|                 COROUTINE FRAME (ON HEAP)                     |
+---------------------------------------------------------------+
|  1. State Index / Instruction Pointer  (Where are we paused?) |
|  2. promise_type handle       (Our data bridge)               |   -> manages return values, stores captured exceptions etc
|  3. Function Parameters                (Copies of arguments)  |
|  4. Local Variables                    (Persist across pauses)|
+---------------------------------------------------------------+


2. What is promise_type handle?

The promise_type is the internal configuration and data bridge between the coroutine body and the outside caller.
It defines these critical behaviours:
        -> Stores the value when co_yield local_val is executed in the coroutine function. that local_val is
            stored in the heap. How does the caller use this value?: A wrapper class (usually called "Generator")
            is responsible for an object of type <promise_type> (often called "Handle") and returning the value of 
            handle.stored_value_on_heap; See Generator class below.
        -> Start Behaviour (initial_suspend): whether to run the coroutine immediately upon creation or pause right
            at the beginning. 
        -> End Behaviour (final_suspend): what to do when the coroutine hits its closing } or co_return.

3. Execution:
    FOLLOW main2(){} example.
    -> STEP 1: Creation and Starting:       
        1. main() calls a coroutine.      
        2. compiler allocates a heap frame for the coroutine.
        3. compiler constructs promise_type inside that heap.
        4. compiler calls get_return_object(), a generator is created on the caller's stack. caller: main2(), generator: gen
        5. coroutine calls initial_suspend().

    -> STEP 2: 
        remaning code should be easy to understand in main2(). see the code for generator below.
*/


/*
! co_await

any function which uses a co_await becomes a coroutine. main(), constructors, destructors etc cannot be coroutines, and
cannot use co_await.

to use co_await, we write this in the coroutine:

Generator<x> co_await_ex(){
    Result res = co_await some_task;
}

Result is a type which is produced by some_task (which runs asynchronously). some_task is a struct with 3 functions:
    1. bool await_ready(): 
        -> is the result already available? if so, why do we need to wait, just continue execution 
            in the coroutine. Return true to continue exection, false to stop the coroutine to stop.

    2. void await_suspend(std::coroutine_handle<> h): 
        -> h is the handle of the coroutine. we handover h to a background process so it can resume us later.
        -> the background process should call h.resume() to resume the coroutine.

    3. Result await_resume():
        -> return the value produces by the background process.


Execution:
    FOLLOW some_task() and co_await_main() code below.
    -> STEP 1: Creation and Starting:       
        1. co_await_main() calls a coroutine, some_task().      
        2. compiler allocates a heap frame for the some_task().
        3. compiler constructs promise_type inside that heap.
        4. compiler calls get_return_object() of Task, a generator is created on the caller's stack. caller: co_await_main(), generator is ignored.

    -> STEP 2: co_await Pausing:
        1. the coroutine reaches co_await using the main thread.
        2. compiler constructs the temporary MyAwaitable object.
        3. compiler calls awaitable.await_ready() -> returns false -> The data is not ready -> the coroutine pauses.
        4. compiler passes the coroutine's remote control (std::coroutine_handle) into awaitable.await_suspend(handle)

    -> Step 3: Suspension and Handoff:
        1. inside await_suspend(handle), the handle is handed off to an asynchronous system.
        2. the main thread returns to co_await_main(), not blocked by the asynchronous system.

    -> Step 4: Resumption:
        1. the background task finishes its work and writes the output into awaitable.data.
        2. the background task calls h.resume();
        3. the coroutine resumes from the co_await line.

*/


// ! for co_return, we need to add/modify functions in promise_type struct.


template <typename T>
class Generator{
public:
    struct promise_type{
        T heap_val;

        Generator get_return_object(){
            return Generator(std::coroutine_handle<promise_type>::from_promise(*this));
        }

        std::suspend_always initial_suspend() { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        std::suspend_always yield_value(const T& val){
            heap_val = val;
            return {};
        }
        std::suspend_always yield_value(T&& val){
            heap_val = std::move(val);
            return {};
        }

        void return_void() {}
        void unhandled_exception() { std::terminate(); }
    };

    std::coroutine_handle<promise_type> handle;

    Generator(std::coroutine_handle<promise_type> h) : handle(h) {}
    ~Generator(){
        if(handle)
            handle.destroy();
    }

    bool done(){
        if(handle && !handle.done())
            return false;
        return true;
    }

    const T& get_value() const {
        return handle.promise().heap_val;
    }

    void continue_exec(){
        if(done())
            return;
        handle.resume();
    }
};


Generator<int> coroutine_ex(){
    std::cout << "Hello! Doing some work here, produced the value 10!" << std::endl;
    co_yield 10;

    std::cout << "Doing some work again, produced the value 20!" << std::endl;
    co_yield 20;

    std::cout << "Doing some work for the last time, produced the value 30!" << std::endl;
    co_yield 30;
}

void main2(){
    Generator<int> gen = coroutine_ex();

    while(!gen.done()){
        gen.continue_exec();
        int num = gen.get_value();
        std::cout << "Coroutine produced the value: " << num << std::endl;
    }
    // * small bug: "Coroutine produced the value: 30" is printed twice, because the coroutine executes after the
    // * final co_yield, because it hasn't seen co_return yet. be careful.
}



// As all coroutines need to return a wrapper (Generator) wrapped over promise_type, we create this class
class Task{
public:
    struct promise_type{
        Task get_return_object(){ return {}; }
        std::suspend_never initial_suspend() { return {}; }
        std::suspend_never final_suspend() noexcept {return {}; }
        void return_void(){}
        void unhandled_exception() { std::terminate(); }
    };
};

struct MyAwaitable{
    std::string data;

    bool await_ready(){
        return false;   // always pauses the coroutine
    }

    void await_suspend(std::coroutine_handle<> h){
        std::thread(    // background process
            [h, this](){
                this->data = "Some data produced by the background process";
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                h.resume(); // resumes the coroutine
            }
        ).detach();
    }

    std::string await_resume(){
        return data;
    }
};

Task some_task(){
    std::cout << "[Coroutine] Thread id (Main thread): " << std::this_thread::get_id() << std::endl;
    std::cout << "[Coroutine] Waiting for data to be produced." << std::endl;
    std::string produced_data = co_await MyAwaitable{};
    std::cout << "[Coroutine] Woke up. THREAD ID: " << std::this_thread::get_id() << std::endl;
    std::cout << "[Coroutine] After the data is produced, function woke up." << std::endl;
    std::cout << "[Coroutine] Produced data : " << produced_data << std::endl;
    std::cout << "[Coroutine] !!! BECAUSE the thread in await_suspend() called h.resume(), the background thread is resuming this function." << std::endl;
    co_return;
}

void co_await_main(){
    std::cout << "[main] THREAD ID: " << std::this_thread::get_id() << std::endl;
    some_task();
    std::cout << "[main] The main thread is not blocked. some_task() runs on the main thread too." << std::endl;
    std::cout << "[main] THREAD ID: " << std::this_thread::get_id() << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
}


int main(){
    std::cout << "COROUTINE BASICS:" << std::endl << std::endl;;
    main2();

    std::cout << std::endl << std::endl << "COAWAIT BASICS:" << std::endl << std::endl;
    co_await_main();
    return 0;
}