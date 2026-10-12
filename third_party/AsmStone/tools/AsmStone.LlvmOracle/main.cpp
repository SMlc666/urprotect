#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/TargetParser/Triple.h"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace llvm;

namespace {

constexpr uint32_t DefaultChunkSize = 1u << 20;
constexpr uint64_t Address = 0;

struct ChunkResult {
  uint64_t Start = 0;
  uint32_t Count = 0;
  uint32_t ValidCount = 0;
  uint32_t SoftFailCount = 0;
  std::array<uint8_t, 32> Digest{};
  std::vector<uint8_t> SoftFailMask;
};

bool ParseUnsigned(const char *Text, uint64_t &Value) {
  if (Text == nullptr || *Text == '\0')
    return false;

  errno = 0;
  char *End = nullptr;
  unsigned long long Parsed = std::strtoull(Text, &End, 0);
  if (errno != 0 || End == Text || *End != '\0')
    return false;

  Value = static_cast<uint64_t>(Parsed);
  return true;
}

bool ReadOption(const char *Argument, const char *Name, uint64_t &Value) {
  const size_t Length = std::strlen(Name);
  if (std::strncmp(Argument, Name, Length) != 0 || Argument[Length] != '=')
    return false;
  return ParseUnsigned(Argument + Length + 1, Value);
}

void UpdateU8(SHA256 &Hash, uint8_t Value) {
  Hash.update(ArrayRef<uint8_t>(&Value, 1));
}

void UpdateU32(SHA256 &Hash, uint32_t Value) {
  uint8_t Bytes[4];
  support::endian::write32le(Bytes, Value);
  Hash.update(ArrayRef<uint8_t>(Bytes, sizeof(Bytes)));
}

void UpdateString(SHA256 &Hash, StringRef Value) {
  uint16_t Length = static_cast<uint16_t>(Value.size());
  uint8_t LengthBytes[2];
  support::endian::write16le(LengthBytes, Length);
  Hash.update(ArrayRef<uint8_t>(LengthBytes, sizeof(LengthBytes)));
  Hash.update(Value);
}

uint8_t SemanticFlags(const MCInstrDesc &Descriptor) {
  uint8_t Flags = 0;
  if (Descriptor.isCompare())
    Flags |= 1u << 0;
  if (Descriptor.isBranch())
    Flags |= 1u << 1;
  if (Descriptor.isCall())
    Flags |= 1u << 2;
  if (Descriptor.isReturn())
    Flags |= 1u << 3;
  if (Descriptor.isBarrier())
    Flags |= 1u << 4;
  if (Descriptor.isTerminator())
    Flags |= 1u << 5;
  return Flags;
}

void UpdateRecord(
    SHA256 &Hash,
    bool Valid,
    uint8_t Flags,
    uint32_t Reencoded,
    StringRef OpcodeName) {
  UpdateU8(Hash, Valid ? 1 : 0);
  UpdateU8(Hash, Flags);
  UpdateU32(Hash, Reencoded);
  UpdateString(Hash, OpcodeName);
}

void WriteU32(uint32_t Value) {
  uint8_t Bytes[4];
  support::endian::write32le(Bytes, Value);
  std::fwrite(Bytes, 1, sizeof(Bytes), stdout);
}

void WriteU64(uint64_t Value) {
  uint8_t Bytes[8];
  support::endian::write64le(Bytes, Value);
  std::fwrite(Bytes, 1, sizeof(Bytes), stdout);
}

bool WriteResult(const ChunkResult &Result) {
  WriteU64(Result.Start);
  WriteU32(Result.Count);
  WriteU32(Result.ValidCount);
  WriteU32(Result.SoftFailCount);
  if (std::fwrite(Result.Digest.data(), 1, Result.Digest.size(), stdout)
      != Result.Digest.size()) {
    return false;
  }
  if (std::fwrite(
          Result.SoftFailMask.data(),
          1,
          Result.SoftFailMask.size(),
          stdout)
      != Result.SoftFailMask.size()) {
    return false;
  }
  return std::fflush(stdout) == 0;
}

class Oracle {
public:
  Oracle() {
    InitializeAllTargetInfos();
    InitializeAllTargetMCs();
    InitializeAllDisassemblers();

    Triple TheTriple("aarch64-unknown-linux-gnu");
    std::string Error;
    TheTarget = TargetRegistry::lookupTarget(TheTriple, Error);
    if (TheTarget == nullptr) {
      std::fprintf(stderr, "LLVM target lookup failed: %s\n", Error.c_str());
      return;
    }

    RegisterInfo.reset(TheTarget->createMCRegInfo(TheTriple));
    AsmInfo.reset(TheTarget->createMCAsmInfo(*RegisterInfo, TheTriple, Options));
    SubtargetInfo.reset(
        TheTarget->createMCSubtargetInfo(TheTriple, "generic", "+all"));
    if (!RegisterInfo || !AsmInfo || !SubtargetInfo) {
      std::fprintf(stderr, "LLVM AArch64 MC object creation failed.\n");
      return;
    }

    Context = std::make_unique<MCContext>(
        TheTriple, *AsmInfo, *RegisterInfo, *SubtargetInfo);
    InstructionInfo.reset(TheTarget->createMCInstrInfo());
    Disassembler.reset(
        TheTarget->createMCDisassembler(*SubtargetInfo, *Context));
    Emitter.reset(TheTarget->createMCCodeEmitter(*InstructionInfo, *Context));
    Ready = InstructionInfo && Disassembler && Emitter;
  }

  bool IsReady() const { return Ready; }

  ChunkResult RunChunk(uint64_t Start, uint32_t Count, bool Dump) {
    ChunkResult Result;
    Result.Start = Start;
    Result.Count = Count;
    Result.SoftFailMask.resize((Count + 7) / 8);
    SHA256 Hash;

    for (uint32_t Offset = 0; Offset < Count; ++Offset) {
      const uint32_t Word = static_cast<uint32_t>(Start + Offset);
      MCInst Instruction;
      uint64_t Size = 0;
      const uint8_t Bytes[4] = {
          static_cast<uint8_t>(Word),
          static_cast<uint8_t>(Word >> 8),
          static_cast<uint8_t>(Word >> 16),
          static_cast<uint8_t>(Word >> 24),
      };
      const auto Status = Disassembler->getInstruction(
          Instruction,
          Size,
          ArrayRef<uint8_t>(Bytes, sizeof(Bytes)),
          Address,
          nulls());
      if (Status == MCDisassembler::Fail) {
        if (Dump) {
          std::fprintf(stdout, "%08X F\n", Word);
        } else {
          UpdateRecord(Hash, false, 0, 0, StringRef());
        }
        continue;
      }

      if (Status == MCDisassembler::SoftFail) {
        if (Dump) {
          std::fprintf(stdout, "%08X S\n", Word);
        } else {
          ++Result.SoftFailCount;
          Result.SoftFailMask[Offset / 8] |= static_cast<uint8_t>(1u << (Offset % 8));
        }
        continue;
      }
      if (!Dump)
        ++Result.ValidCount;

      SmallVector<char, 16> Encoded;
      SmallVector<MCFixup, 4> Fixups;
      Emitter->encodeInstruction(
          Instruction, Encoded, Fixups, *SubtargetInfo);
      uint32_t Reencoded = 0;
      if (Encoded.size() >= 4) {
        Reencoded = support::endian::read32le(Encoded.data());
      }

      const MCInstrDesc &Descriptor = InstructionInfo->get(Instruction.getOpcode());
      const StringRef OpcodeName = InstructionInfo->getName(Instruction.getOpcode());
      if (Dump) {
        std::fprintf(
            stdout,
            "%08X V %08X %.*s\n",
            Word,
            Reencoded,
            static_cast<int>(OpcodeName.size()),
            OpcodeName.data());
      } else {
        UpdateRecord(
            Hash,
            true,
            SemanticFlags(Descriptor),
            Reencoded,
            OpcodeName);
      }
    }

    if (Dump)
      std::fflush(stdout);
    Result.Digest = Hash.final();
    return Result;
  }

private:
  const Target *TheTarget = nullptr;
  MCTargetOptions Options;
  std::unique_ptr<MCRegisterInfo> RegisterInfo;
  std::unique_ptr<MCAsmInfo> AsmInfo;
  std::unique_ptr<MCSubtargetInfo> SubtargetInfo;
  std::unique_ptr<MCContext> Context;
  std::unique_ptr<MCInstrInfo> InstructionInfo;
  std::unique_ptr<MCDisassembler> Disassembler;
  std::unique_ptr<MCCodeEmitter> Emitter;
  bool Ready = false;
};

} // namespace

int main(int argc, char **argv) {
  InitLLVM Init(argc, argv);
  uint64_t Start = 0;
  uint64_t Count = 0;
  uint64_t ChunkSize = DefaultChunkSize;
  bool Dump = false;

  for (int Index = 1; Index < argc; ++Index) {
    if (std::strcmp(argv[Index], "--dump") == 0) {
      Dump = true;
      continue;
    }

    if (ReadOption(argv[Index], "--start", Start)
        || ReadOption(argv[Index], "--count", Count)
        || ReadOption(argv[Index], "--chunk-size", ChunkSize)) {
      continue;
    }

    std::fprintf(stderr, "Unknown or invalid option: %s\n", argv[Index]);
    return 2;
  }

  if (Count == 0 || ChunkSize == 0 || Start > (1ull << 32)
      || Count > (1ull << 32) - Start || ChunkSize > UINT32_MAX) {
    std::fprintf(stderr, "Invalid range or chunk size.\n");
    return 2;
  }

  Oracle Instance;
  if (!Instance.IsReady())
    return 3;

  if (Dump) {
    uint64_t Completed = 0;
    while (Completed < Count) {
      const uint64_t Remaining = Count - Completed;
      const uint32_t Current = static_cast<uint32_t>(
          Remaining < ChunkSize ? Remaining : ChunkSize);
      Instance.RunChunk(Start + Completed, Current, true);
      Completed += Current;
    }
    return 0;
  }

  uint64_t Completed = 0;
  while (Completed < Count) {
    const uint64_t Remaining = Count - Completed;
    const uint32_t Current = static_cast<uint32_t>(
        Remaining < ChunkSize ? Remaining : ChunkSize);
    const ChunkResult Result = Instance.RunChunk(Start + Completed, Current, false);
    if (!WriteResult(Result))
      return 4;
    Completed += Current;
  }

  return 0;
}
