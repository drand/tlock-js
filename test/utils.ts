import {AssertionError} from "chai"

export async function assertError(fn: () => Promise<unknown>, message?: string): Promise<void> {
    let result = null
    try {
        result = await fn()
    } catch (err) {
        return
    }
    throw new AssertionError(message ?? `Expected error, but received ${JSON.stringify(result)}`)
}

export async function assertErrorMessage(fn: () => Promise<unknown>, expectedMessage: string): Promise<void> {
    let result = null
    try {
        result = await fn()

    // eslint-disable-next-line  @typescript-eslint/no-explicit-any
    } catch (err: any) {
        if (err == expectedMessage || err.message === expectedMessage) {
            return
        }
        throw new AssertionError(`Received an error, but was ${err} instead of ${expectedMessage}`)
    }
    throw new AssertionError(`Expected error, but received ${JSON.stringify(result)}`)
}
