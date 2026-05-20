module insecure_key_regs(
    input logic clk,
    input logic bus_write,
    input logic [31:0] host_wdata
);
    always_ff @(posedge clk) begin
        if (bus_write) begin
            boot_key <= host_wdata;
        end
    end
endmodule

module secure_key_regs(
    input logic clk,
    input logic bus_write,
    input logic is_privileged,
    input logic lifecycle_secure,
    input logic [31:0] host_wdata
);
    always_ff @(posedge clk) begin
        if (bus_write && is_privileged && lifecycle_secure) begin
            boot_key <= host_wdata;
        end
    end
endmodule

module boot_key_shadow;
    always_ff @(posedge clk) begin
        boot_key <= BOOT_ROM_KEY;
    end
endmodule
