import Foundation

// This code was sourced from Paulo Tanaka, and modified by Tanner Silva in 2019 for compatibility with the swift package manager on Linux.
fileprivate struct ANSIColorCode {
    static let black = [0, 9]
    static let red = [1, 9]
    static let green = [2, 9]
    static let yellow = [3, 9]
    static let blue = [4, 9]
    static let magenta = [5, 9]
    static let cyan = [6, 9]
    static let white = [7, 9]
}
fileprivate struct ANSIModifiers {
    static let bold = [1, 22]
    static let blink = [5, 25]
    static let dim = [2, 22]
    static let italic = [2, 23]
    static let underline = [4, 24]
    static let inverse = [7, 27]
    static let hidden = [8, 28]
    static let strikethrough = [9, 29]
}

fileprivate func apply<T>(style: [T]) -> ((_:String) -> String) {
    return { str in return "\u{001B}[\(style[0])m\(str)\u{001B}[\(style[1])m" }
}

fileprivate func getColor(color: [Int], mod: Int) -> [Int] {
    let terminator = mod == 30 || mod == 90 ? 30 : 40
    return [ color[0] + mod, color[1] + terminator ]
}

public class Colors {
    fileprivate static let normalText = 30
    fileprivate static let bg = 40
    fileprivate static let brightText = 90
    fileprivate static let brightBg = 100

    // MARK: 8-bit color functions
    public static func getTextColorer(color: Int) -> ((_:String) -> String) {
        return apply(style:["38;5;\(color)", String(normalText + 9)])
    }

    public static func colorText(text: String, color: Int) -> String {
        return Colors.getTextColorer(color:color)(text)
    }

    public static func getBgColorer(color: Int) -> ((_:String) -> String) {
        return apply(style:["48;5;\(color)", String(bg + 9)])
    }

    public static func colorBg(text: String, color: Int) -> String {
        return Colors.getBgColorer(color:color)(text)
    }

    // MARK: Normal text colors
	nonisolated(unsafe) public static let black = apply(style:getColor(color:ANSIColorCode.black, mod: normalText))
    nonisolated(unsafe) public static let red = apply(style:getColor(color:ANSIColorCode.red, mod: normalText))
    nonisolated(unsafe) public static let green = apply(style:getColor(color:ANSIColorCode.green, mod: normalText))
    nonisolated(unsafe) public static let yellow = apply(style:getColor(color:ANSIColorCode.yellow, mod: normalText))
    nonisolated(unsafe) public static let blue = apply(style:getColor(color:ANSIColorCode.blue, mod: normalText))
    nonisolated(unsafe) public static let magenta = apply(style:getColor(color:ANSIColorCode.magenta, mod: normalText))
    nonisolated(unsafe) public static let cyan = apply(style:getColor(color:ANSIColorCode.cyan, mod: normalText))
    nonisolated(unsafe) public static let white = apply(style:getColor(color:ANSIColorCode.white, mod: normalText))

    // MARK: Bright text colors
    nonisolated(unsafe) public static let Black = apply(style:getColor(color:ANSIColorCode.black, mod: brightText))
    nonisolated(unsafe) public static let Red = apply(style:getColor(color:ANSIColorCode.red, mod: brightText))
    nonisolated(unsafe) public static let Green = apply(style:getColor(color:ANSIColorCode.green, mod: brightText))
    nonisolated(unsafe) public static let Yellow = apply(style:getColor(color:ANSIColorCode.yellow, mod: brightText))
    nonisolated(unsafe) public static let Blue = apply(style:getColor(color:ANSIColorCode.blue, mod: brightText))
    nonisolated(unsafe) public static let Magenta = apply(style:getColor(color:ANSIColorCode.magenta, mod: brightText))
    nonisolated(unsafe) public static let Cyan = apply(style:getColor(color:ANSIColorCode.cyan, mod: brightText))
    nonisolated(unsafe) public static let White = apply(style:getColor(color:ANSIColorCode.white, mod: brightText))

    // MARK: Normal background colors
    nonisolated(unsafe) public static let bgBlack = apply(style:getColor(color:ANSIColorCode.black, mod: bg))
    nonisolated(unsafe) public static let bgRed = apply(style:getColor(color:ANSIColorCode.red, mod: bg))
    nonisolated(unsafe) public static let bgGreen = apply(style:getColor(color:ANSIColorCode.green, mod: bg))
    nonisolated(unsafe) public static let bgYellow = apply(style:getColor(color:ANSIColorCode.yellow, mod: bg))
    nonisolated(unsafe) public static let bgBlue = apply(style:getColor(color:ANSIColorCode.blue, mod: bg))
    nonisolated(unsafe) public static let bgMagenta = apply(style:getColor(color:ANSIColorCode.magenta, mod: bg))
    nonisolated(unsafe) public static let bgCyan = apply(style:getColor(color:ANSIColorCode.cyan, mod: bg))
    nonisolated(unsafe) public static let bgWhite = apply(style:getColor(color:ANSIColorCode.white, mod: bg))

    // MARK: Bright background colors
    nonisolated(unsafe) public static let BgBlack = apply(style:getColor(color:ANSIColorCode.black, mod: brightBg))
    nonisolated(unsafe) public static let BgRed = apply(style:getColor(color:ANSIColorCode.red, mod: brightBg))
    nonisolated(unsafe) public static let BgGreen = apply(style:getColor(color:ANSIColorCode.green, mod: brightBg))
    nonisolated(unsafe) public static let BgYellow = apply(style:getColor(color:ANSIColorCode.yellow, mod: brightBg))
    nonisolated(unsafe) public static let BgBlue = apply(style:getColor(color:ANSIColorCode.blue, mod: brightBg))
    nonisolated(unsafe) public static let BgMagenta = apply(style:getColor(color:ANSIColorCode.magenta, mod: brightBg))
    nonisolated(unsafe) public static let BgCyan = apply(style:getColor(color:ANSIColorCode.cyan, mod: brightBg))
    nonisolated(unsafe) public static let BgWhite = apply(style:getColor(color:ANSIColorCode.white, mod: brightBg))

    // MARK: Text modifiers
    nonisolated(unsafe) public static let bold = apply(style:ANSIModifiers.bold)
    nonisolated(unsafe) public static let blink = apply(style:ANSIModifiers.blink)
    nonisolated(unsafe) public static let dim = apply(style:ANSIModifiers.dim)
    nonisolated(unsafe) public static let italic = apply(style:ANSIModifiers.italic)
    nonisolated(unsafe) public static let underline = apply(style:ANSIModifiers.underline)
    nonisolated(unsafe) public static let inverse = apply(style:ANSIModifiers.inverse)
    nonisolated(unsafe) public static let hidden = apply(style:ANSIModifiers.hidden)
    nonisolated(unsafe) public static let strikethrough = apply(style:ANSIModifiers.strikethrough)
}
