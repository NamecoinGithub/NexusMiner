#ifndef NEXUSMINER_PROTOCOL_SUBMIT_RESULT_GATE_HPP
#define NEXUSMINER_PROTOCOL_SUBMIT_RESULT_GATE_HPP

namespace nexusminer {
namespace protocol {

class SubmitResultGate {
public:
    void mark_pending() noexcept { m_pending = true; }
    void clear() noexcept { m_pending = false; }
    bool has_pending() const noexcept { return m_pending; }

    bool consume_pending() noexcept
    {
        if (!m_pending) {
            return false;
        }
        m_pending = false;
        return true;
    }

private:
    bool m_pending{false};
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_SUBMIT_RESULT_GATE_HPP
