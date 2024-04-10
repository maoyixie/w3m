#include <stdint.h>
#include <stdlib.h>
#include <gc.h>
#include "wc.h"
#include "wtf.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size == 0)
    {
        return 0;
    }

    // Prepare input and target character encoding sets
    wc_ces from_ces = WC_CES_US_ASCII;
    wc_ces to_ces = WC_CES_UTF_8;

    // Create an input Str object from the fuzzer data
    Str input_str = Strnew_size(Size);
    for (size_t i = 0; i < Size; i++)
    {
        input_str->ptr[i] = (char)Data[i];
    }
    input_str->length = Size;

    // Call the target function to be fuzzed
    wc_ces detected_ces;
    Str result = wc_Str_conv_with_detect(input_str, &detected_ces, from_ces, to_ces);

    // Clean up resources
    Strfree(input_str);
    Strfree(result);

    return 0;
}