defmodule MonitorPackets do
  use Honey, license: "GPL-2.0"

  @max_entries 1024
  @threshold_bytes 1000

  defmap(:protocol_bytes, :bpf_array, [max_entries: 335, print: true])

  defmap(:src_ip_bytes, :bpf_array, [max_entries: @max_entries, print: true])

  defmap(:events, :bpf_array, [max_entries: 1024, print: true])

  defstruct anomaly_event: %{src_ip: :u32, total_bytes: :u64}

  @sec "xdp"
  def main(ctx) do
    data = ctx.data
    data_end = ctx.data_end

    if data + 14 > data_end, do: return(:xdp_pass)

    eth_proto = Honey.load_u16(data + 12) |> Honey.ntohs()

    if eth_proto != 0x0800, do: return(:xdp_pass)

    ip_offset = 14
    if data + ip_offset + 20 > data_end, do: return(:xdp_pass)

    proto = Honey.load_u8(data + ip_offset + 9)
    src_ip = Honey.load_u32(data + ip_offset + 12)
    pkt_len = data_end - data

    case Honey.bpf_map_lookup_elem(:protocol_bytes, proto) do
      nil -> Honey.bpf_map_update_elem(:protocol_bytes, proto, pkt_len, :any)
      val ->
        new_val = val + pkt_len
        Honey.bpf_map_update_elem(:protocol_bytes, proto, new_val, :any)
    end

    case Honey.bpf_map_lookup_elem(:src_ip_bytes, src_ip) do
      nil ->
        Honey.bpf_map_update_elem(:src_ip_bytes, src_ip, pkt_len, :any)

      val ->
        new_val = val + pkt_len
        Honey.bpf_map_update_elem(:src_ip_bytes, src_ip, new_val, :any)

        if new_val > @threshold_bytes do
          evt = %{src_ip: src_ip, total_bytes: new_val}
          Honey.bpf_perf_event_output(ctx, :events, :current_cpu, evt)
        end
    end

    :xdp_pass
  end
end
